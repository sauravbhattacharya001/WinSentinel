using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the PrivacyAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class PrivacyAuditTests
{
    private readonly PrivacyAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Privacy Audit", _audit.Name);
        Assert.Equal("Privacy", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Privacy Audit", result.ModuleName);
        Assert.Equal("Privacy", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should have findings from multiple privacy checks
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
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

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

    [Fact]
    public async Task RunAuditAsync_ChecksTelemetry()
    {
        var result = await _audit.RunAuditAsync();

        // Should have at least one telemetry-related finding
        var telemetryFindings = result.Findings
            .Where(f => f.Title.Contains("Telemetry", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(telemetryFindings);
    }
}
