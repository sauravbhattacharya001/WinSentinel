using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Comprehensive tests for the AppSecurityAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class AppSecurityAuditTests
{
    private readonly AppSecurityAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("App Security Audit", _audit.Name);
        Assert.Equal("Applications", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
        Assert.Contains("outdated", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("end-of-life", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("App Security Audit", result.ModuleName);
        Assert.Equal("Applications", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should have at minimum: EOL check result, install locations, bloatware check,
        // store auto-update check, and installed programs summary
        Assert.True(result.Findings.Count >= 4,
            $"Expected at least 4 findings, got {result.Findings.Count}");
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
            Assert.Equal("Applications", finding.Category);
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
        }
    }

    [Fact]
    public async Task RunAuditAsync_ContainsEolCheck()
    {
        var result = await _audit.RunAuditAsync();

        // Should have either an EOL finding or a "No EOL Software" pass
        var eolFindings = result.Findings
            .Where(f => f.Title.Contains("EOL", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("end-of-life", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("No EOL", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(eolFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsInstallLocationCheck()
    {
        var result = await _audit.RunAuditAsync();

        var locationFindings = result.Findings
            .Where(f => f.Title.Contains("Install Location", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Suspicious Install", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(locationFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsBloatwareCheck()
    {
        var result = await _audit.RunAuditAsync();

        var bloatwareFindings = result.Findings
            .Where(f => f.Title.Contains("Program", StringComparison.OrdinalIgnoreCase) &&
                        (f.Title.Contains("Count", StringComparison.OrdinalIgnoreCase) ||
                         f.Title.Contains("Excessive", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        Assert.NotEmpty(bloatwareFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsStoreAutoUpdateCheck()
    {
        var result = await _audit.RunAuditAsync();

        var storeFindings = result.Findings
            .Where(f => f.Title.Contains("Store", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(storeFindings);
    }

    [Fact]
    public async Task RunAuditAsync_ContainsProgramsSummary()
    {
        var result = await _audit.RunAuditAsync();

        var summaryFindings = result.Findings
            .Where(f => f.Title.Contains("Summary", StringComparison.OrdinalIgnoreCase) ||
                        f.Title.Contains("Installed Programs", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(summaryFindings);
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
            Assert.Equal("Applications", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_DurationIsReasonable()
    {
        var result = await _audit.RunAuditAsync();

        // Registry enumeration should complete in under 15 seconds
        Assert.True(result.Duration < TimeSpan.FromSeconds(15),
            $"Audit took too long: {result.Duration}");
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            var result = await _audit.RunAuditAsync(cts.Token);
            Assert.NotNull(result);
        }
        catch (OperationCanceledException)
        {
            // Also acceptable
        }
    }

    [Fact]
    public async Task RunAuditAsync_MultipleRunsAreConsistent()
    {
        var result1 = await _audit.RunAuditAsync();
        var result2 = await _audit.RunAuditAsync();

        Assert.True(result1.Success);
        Assert.True(result2.Success);

        // Finding counts should be the same (nothing changed between runs)
        Assert.Equal(result1.Findings.Count, result2.Findings.Count);

        // Same finding titles
        var titles1 = result1.Findings.Select(f => f.Title).OrderBy(t => t).ToList();
        var titles2 = result2.Findings.Select(f => f.Title).OrderBy(t => t).ToList();
        Assert.Equal(titles1, titles2);
    }

    [Fact]
    public async Task RunAuditAsync_DetectsInstalledPrograms()
    {
        var result = await _audit.RunAuditAsync();

        // The summary finding should report a positive number of installed programs
        var summary = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Summary", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(summary);
        Assert.Contains("Total installed programs:", summary.Description);
        // Every Windows machine has at least some programs
        Assert.DoesNotContain("Total installed programs: 0", summary.Description);
    }

    #region ParseVersion Unit Tests

    [Theory]
    [InlineData("24.09", 24, 9)]
    [InlineData("3.0.20.0", 3, 0)]
    [InlineData("v20.11.0", 20, 11)]
    [InlineData("2.43.0.windows.1", 2, 43)]
    [InlineData("7.00", 7, 0)]
    [InlineData("0.80", 0, 80)]
    [InlineData("8.6.4", 8, 6)]
    [InlineData("3.12.1", 3, 12)]
    [InlineData("24.0", 24, 0)]
    [InlineData("133.0.6943.0", 133, 0)]
    public void ParseVersion_ValidVersions_ReturnsParsedVersion(
        string input, int expectedMajor, int expectedMinor)
    {
        var version = AppSecurityAudit.ParseVersion(input);

        Assert.NotNull(version);
        Assert.Equal(expectedMajor, version!.Major);
        Assert.Equal(expectedMinor, version.Minor);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ParseVersion_NullOrEmpty_ReturnsNull(string? input)
    {
        var version = AppSecurityAudit.ParseVersion(input);
        Assert.Null(version);
    }

    [Fact]
    public void ParseVersion_VersionWithText_ExtractsVersion()
    {
        var version = AppSecurityAudit.ParseVersion("Version 3.66.2 beta");
        Assert.NotNull(version);
        Assert.Equal(3, version!.Major);
        Assert.Equal(66, version.Minor);
    }

    #endregion
}
