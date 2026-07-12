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

    #region EOL Pattern Matching (Java 8 build-number bounds + general)

    // Java 8 builds below 8u401 must be flagged as outdated. The previous regex
    // (`[1-3]\d{0,2}|40[0-0]?`) silently MISSED every old build whose update
    // number started with 4-9 below 401 (8u45, 8u51, 8u60, 8u66, 8u71, 8u91, ...)
    // — all real, vulnerable releases. These are the regression cases.
    [Theory]
    [InlineData("Java 8 Update 1")]
    [InlineData("Java 8 Update 45")]   // was missed by the old pattern
    [InlineData("Java 8 Update 51")]   // was missed
    [InlineData("Java 8 Update 60")]   // was missed
    [InlineData("Java 8 Update 66")]   // was missed
    [InlineData("Java 8 Update 71")]   // was missed
    [InlineData("Java 8 Update 91")]   // was missed
    [InlineData("Java 8 Update 202")]
    [InlineData("Java 8 Update 351")]
    [InlineData("Java 8 Update 392")]
    [InlineData("Java 8 Update 400")]  // inclusive upper bound (<401)
    [InlineData("Java(TM) SE Development Kit 8 Update 202 (64-bit)")]
    [InlineData("Java SE Runtime Environment 8 Update 91 (64-bit)")]
    public void MatchEolPattern_OldJava8Build_IsFlaggedAsWarning(string displayName)
    {
        var match = AppSecurityAudit.MatchEolPattern(displayName);

        Assert.NotNull(match);
        Assert.Equal("Java 8 (old build)", match!.Value.Name);
        Assert.Equal(Severity.Warning, match.Value.Severity);
    }

    // 8u401 and above are the current/safe builds — they must NOT match the
    // "old build" pattern (no false positive on patched Java 8).
    [Theory]
    [InlineData("Java 8 Update 401")]
    [InlineData("Java 8 Update 411")]
    [InlineData("Java 8 Update 451")]
    [InlineData("Java 8 Update 999")]
    [InlineData("Java SE Runtime Environment 8 Update 401 (64-bit)")]
    public void MatchEolPattern_CurrentJava8Build_IsNotFlaggedAsOldBuild(string displayName)
    {
        var match = AppSecurityAudit.MatchEolPattern(displayName);

        // Either no match at all, or (defensively) not the "old build" pattern.
        if (match is not null)
            Assert.NotEqual("Java 8 (old build)", match.Value.Name);
    }

    // Exhaustive bound check: "Java 8 Update N" must be flagged iff N <= 400.
    [Fact]
    public void MatchEolPattern_Java8UpdateNumber_FlaggedIffBelow401()
    {
        for (int n = 1; n <= 600; n++)
        {
            var match = AppSecurityAudit.MatchEolPattern($"Java 8 Update {n}");
            bool isOldBuild = match is not null && match.Value.Name == "Java 8 (old build)";
            bool shouldFlag = n <= 400;
            Assert.True(isOldBuild == shouldFlag,
                $"Java 8 Update {n}: flagged-as-old-build={isOldBuild}, expected={shouldFlag}");
        }
    }

    [Theory]
    [InlineData("Adobe Flash Player 32 ActiveX", "Adobe Flash Player", Severity.Critical)]
    [InlineData("Python 2.7.18", "Python 2", Severity.Critical)]
    [InlineData("Internet Explorer", "Internet Explorer", Severity.Warning)]
    [InlineData("Microsoft Silverlight", "Microsoft Silverlight", Severity.Critical)]
    public void MatchEolPattern_KnownEolSoftware_MatchesExpectedPattern(
        string displayName, string expectedName, Severity expectedSeverity)
    {
        var match = AppSecurityAudit.MatchEolPattern(displayName);

        Assert.NotNull(match);
        Assert.Equal(expectedName, match!.Value.Name);
        Assert.Equal(expectedSeverity, match.Value.Severity);
    }

    [Theory]
    [InlineData("Java 17 (64-bit)")]      // current LTS, not EOL
    [InlineData("Google Chrome")]
    [InlineData("7-Zip 24.09")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MatchEolPattern_SafeOrEmpty_ReturnsNull(string? displayName)
    {
        Assert.Null(AppSecurityAudit.MatchEolPattern(displayName));
    }

    #endregion

    #region Sideloading / Developer-Mode Classification

    [Fact]
    public void ClassifySideloadingPolicy_DevMode_TakesPrecedence()
    {
        // Dev mode on, sideloading also on -> DeveloperMode wins (most concerning).
        var state = new AppSecurityAudit.SideloadingState(AllowAllTrustedApps: 1, AllowDevelopmentWithoutDevLicense: 1);
        Assert.Equal(AppSecurityAudit.SideloadingPosture.DeveloperMode,
            AppSecurityAudit.ClassifySideloadingPolicy(state));
    }

    [Fact]
    public void ClassifySideloadingPolicy_DevModeOnly_IsDeveloperMode()
    {
        var state = new AppSecurityAudit.SideloadingState(AllowAllTrustedApps: null, AllowDevelopmentWithoutDevLicense: 1);
        Assert.Equal(AppSecurityAudit.SideloadingPosture.DeveloperMode,
            AppSecurityAudit.ClassifySideloadingPolicy(state));
    }

    [Fact]
    public void ClassifySideloadingPolicy_TrustedAppsOnly_IsSideloadingEnabled()
    {
        var state = new AppSecurityAudit.SideloadingState(AllowAllTrustedApps: 1, AllowDevelopmentWithoutDevLicense: 0);
        Assert.Equal(AppSecurityAudit.SideloadingPosture.SideloadingEnabled,
            AppSecurityAudit.ClassifySideloadingPolicy(state));
    }

    [Theory]
    [InlineData(null, null)]  // not configured (default)
    [InlineData(0, 0)]        // explicitly off
    [InlineData(0, null)]
    public void ClassifySideloadingPolicy_Default_IsLocked(int? trusted, int? dev)
    {
        var state = new AppSecurityAudit.SideloadingState(trusted, dev);
        Assert.Equal(AppSecurityAudit.SideloadingPosture.Locked,
            AppSecurityAudit.ClassifySideloadingPolicy(state));
    }

    [Fact]
    public async Task RunAuditAsync_EmitsSideloadingFinding()
    {
        var result = await _audit.RunAuditAsync();
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Sideloading", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("Developer Mode", StringComparison.OrdinalIgnoreCase));
    }

    #endregion
}
