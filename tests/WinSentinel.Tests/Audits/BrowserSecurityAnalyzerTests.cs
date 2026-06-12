using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.BrowserSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="BrowserSecurityAnalyzer"/>.
/// Unlike <see cref="BrowserAuditTests"/> (which runs against the real machine and can
/// only assert that *some* findings appear), these feed synthetic state and assert the
/// exact severity/title/remediation produced by each decision branch.
/// </summary>
public class BrowserSecurityAnalyzerTests
{
    // ------------------------------------------------------------------
    // NormalizeVersion
    // ------------------------------------------------------------------

    [Theory]
    [InlineData("135", "135.0.0.0")]
    [InlineData("135.0", "135.0.0.0")]
    [InlineData("135.0.1", "135.0.1.0")]
    [InlineData("135.0.1.2", "135.0.1.2")]
    [InlineData("135.0.1.2.3", "135.0.1.2.3")] // 5+ parts returned unchanged
    public void NormalizeVersion_PadsToFourParts(string input, string expected)
    {
        Assert.Equal(expected, NormalizeVersion(input));
    }

    // ------------------------------------------------------------------
    // BuildVersionFinding - Chrome
    // ------------------------------------------------------------------

    [Fact]
    public void Chrome_NotInstalled_NoVersion_IsInfoNotInstalled()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = false, RawVersion = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Chrome Not Installed", f.Title);
        Assert.Equal("Browser", f.Category);
    }

    [Fact]
    public void Chrome_InstalledButNoVersion_IsInfoUnknown()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Chrome Installed (Version Unknown)", f.Title);
    }

    [Fact]
    public void Chrome_OutdatedVersion_IsWarningWithRemediation()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = "120.0.0.0" });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Chrome Outdated", f.Title);
        Assert.Contains("120.0.0.0", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation));
        Assert.Equal("Start-Process 'chrome://settings/help'", f.FixCommand);
    }

    [Fact]
    public void Chrome_CurrentVersion_IsPass()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = LatestChromeVersion.ToString() });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Chrome Up to Date", f.Title);
    }

    [Fact]
    public void Chrome_NewerThanBaseline_IsPass()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = "999.0.0.0" });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Chrome Up to Date", f.Title);
    }

    [Fact]
    public void Chrome_UnparseableVersion_IsInfoInstalled()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = "not-a-version" });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Chrome Installed", f.Title);
    }

    // ------------------------------------------------------------------
    // BuildVersionFinding - Edge (always emits something)
    // ------------------------------------------------------------------

    [Fact]
    public void Edge_NoVersion_IsInfoVersionUnknown()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Edge, Installed = false, RawVersion = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Edge Version Unknown", f.Title);
    }

    [Fact]
    public void Edge_Outdated_IsWarning()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Edge, Installed = true, RawVersion = "100.0.0.0" });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Edge Outdated", f.Title);
        Assert.Equal("Start-Process 'edge://settings/help'", f.FixCommand);
    }

    [Fact]
    public void Edge_Current_IsPass()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Edge, Installed = true, RawVersion = LatestEdgeVersion.ToString() });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Edge Up to Date", f.Title);
    }

    // ------------------------------------------------------------------
    // BuildVersionFinding - Firefox (version strings have suffixes)
    // ------------------------------------------------------------------

    [Fact]
    public void Firefox_NotInstalled_IsInfoNotInstalled()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Firefox, Installed = false, RawVersion = null });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Firefox Not Installed", f.Title);
    }

    [Fact]
    public void Firefox_VersionWithLocaleSuffix_ParsesAndComparesAgainstBaseline()
    {
        // "135.0 (x64 en-US)" should parse to 135.0 and be current.
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Firefox, Installed = true, RawVersion = $"{LatestFirefoxVersion.ToString(3)} (x64 en-US)" });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Firefox Up to Date", f.Title);
    }

    [Fact]
    public void Firefox_OldVersionWithSuffix_IsWarning()
    {
        var f = BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Firefox, Installed = true, RawVersion = "100.0 (x64 en-US)" });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Firefox Outdated", f.Title);
        // Latest is reported to 3 components for Firefox
        Assert.Contains(LatestFirefoxVersion.ToString(3), f.Description);
    }

    // ------------------------------------------------------------------
    // Extensions
    // ------------------------------------------------------------------

    private static ExtensionState Ext(string id, string? name = null, params string[] perms) =>
        new() { Id = id, Name = name, Permissions = perms };

    [Fact]
    public void Extensions_EmptyList_YieldsNoFindings()
    {
        Assert.Empty(AnalyzeExtensions(Array.Empty<ExtensionState>()));
    }

    [Fact]
    public void Extensions_Null_YieldsNoFindings()
    {
        Assert.Empty(AnalyzeExtensions(null!));
    }

    [Fact]
    public void Extensions_CleanExtension_IsPass()
    {
        var findings = AnalyzeExtensions(new[] { Ext("aaaa", "Some Reader", "storage", "alarms") });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Chrome Extensions OK", f.Title);
        Assert.Contains("1 Chrome extension", f.Description);
    }

    [Fact]
    public void Extensions_KnownDangerousId_IsCritical()
    {
        var dangerousId = DangerousExtensionIds.First();
        var findings = AnalyzeExtensions(new[] { Ext(dangerousId, "Bad Ext") });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("Dangerous Chrome Extensions Detected", f.Title);
        Assert.Contains("Bad Ext", f.Description);
        Assert.Equal("Start-Process 'chrome://extensions'", f.FixCommand);
    }

    [Fact]
    public void Extensions_ExcessivePermissions_IsWarning()
    {
        var findings = AnalyzeExtensions(new[] { Ext("bbbb", "Grabby", "debugger", "cookies", "storage") });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Chrome Extensions with Excessive Permissions", f.Title);
        Assert.Contains("debugger", f.Description);
        Assert.Contains("cookies", f.Description);
        Assert.DoesNotContain("storage", f.Description);
    }

    [Fact]
    public void Extensions_DangerousTakesPrecedenceOverPermissions_NoDoubleCount()
    {
        // An extension that is both known-dangerous AND over-permissioned is reported once (as dangerous).
        var dangerousId = DangerousExtensionIds.First();
        var findings = AnalyzeExtensions(new[] { Ext(dangerousId, "Bad", "debugger") });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void Extensions_MixOfDangerousCleanAndExcessive_YieldsCriticalAndWarning_NoPass()
    {
        var dangerousId = DangerousExtensionIds.First();
        var findings = AnalyzeExtensions(new[]
        {
            Ext(dangerousId, "Bad"),
            Ext("clean", "Clean", "storage"),
            Ext("grabby", "Grabby", "proxy"),
        });
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Critical && f.Title == "Dangerous Chrome Extensions Detected");
        Assert.Contains(findings, f => f.Severity == Severity.Warning && f.Title == "Chrome Extensions with Excessive Permissions");
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }

    [Fact]
    public void Extensions_NoName_UsesIdAsLabel()
    {
        var findings = AnalyzeExtensions(new[] { Ext("noname-id", null, "proxy") });
        var f = Assert.Single(findings);
        Assert.Contains("noname-id", f.Description);
    }

    [Fact]
    public void Extensions_HostPermissionWildcard_IsExcessive()
    {
        var findings = AnalyzeExtensions(new[] { Ext("h", "Host", "<all_urls>") });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("<all_urls>", f.Description);
    }

    [Fact]
    public void FindExcessivePermissions_FiltersToDangerousOnly()
    {
        var perms = FindExcessivePermissions(Ext("x", "x", "storage", "proxy", "alarms", "nativeMessaging"));
        Assert.Equal(2, perms.Count);
        Assert.Contains("proxy", perms);
        Assert.Contains("nativeMessaging", perms);
    }

    [Fact]
    public void IsDangerousExtension_EmptyId_False()
    {
        Assert.False(IsDangerousExtension(new ExtensionState { Id = "" }));
    }

    // ------------------------------------------------------------------
    // Auto-update
    // ------------------------------------------------------------------

    [Fact]
    public void AutoUpdate_NoPolicies_IsPass()
    {
        var f = Assert.Single(AnalyzeAutoUpdate(new BrowserPolicyState()));
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Browser Auto-Update Enabled", f.Title);
    }

    [Fact]
    public void AutoUpdate_ChromeUpdateDefaultZero_IsCritical()
    {
        var f = Assert.Single(AnalyzeAutoUpdate(new BrowserPolicyState { ChromeUpdateDefault = 0 }));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("Chrome Auto-Update Disabled", f.Title);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void AutoUpdate_ChromePerAppZero_IsCritical()
    {
        var findings = AnalyzeAutoUpdate(new BrowserPolicyState { ChromePerAppUpdate = 0 });
        Assert.Contains(findings, f => f.Title == "Chrome Auto-Update Disabled");
    }

    [Fact]
    public void AutoUpdate_EdgeUpdateDefaultZero_IsCritical()
    {
        var f = Assert.Single(AnalyzeAutoUpdate(new BrowserPolicyState { EdgeUpdateDefault = 0 }));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("Edge Auto-Update Disabled", f.Title);
    }

    [Fact]
    public void AutoUpdate_BothDisabled_YieldsTwoCriticals_NoPass()
    {
        var findings = AnalyzeAutoUpdate(new BrowserPolicyState { ChromeUpdateDefault = 0, EdgeUpdateDefault = 0 });
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void AutoUpdate_NonZeroValues_AreFine()
    {
        var findings = AnalyzeAutoUpdate(new BrowserPolicyState { ChromeUpdateDefault = 1, EdgeUpdateDefault = 1 });
        Assert.Equal("Browser Auto-Update Enabled", Assert.Single(findings).Title);
    }

    // ------------------------------------------------------------------
    // Safe Browsing / SmartScreen
    // ------------------------------------------------------------------

    [Fact]
    public void SafeBrowsing_NoPolicies_IsPass()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState()));
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Safe Browsing / SmartScreen Enabled", f.Title);
    }

    [Fact]
    public void SafeBrowsing_ChromeLevelZero_IsCritical()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { ChromeSafeBrowsingProtectionLevel = 0 }));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("Chrome Safe Browsing Disabled", f.Title);
    }

    [Fact]
    public void SafeBrowsing_ChromeLegacyDisabled_IsCritical()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { ChromeSafeBrowsingEnabledLegacy = 0 }));
        Assert.Equal("Chrome Safe Browsing Disabled", f.Title);
    }

    [Fact]
    public void SafeBrowsing_ChromeEnhanced_IsNotFlagged()
    {
        // Level 2 = enhanced; should not trigger the disabled finding.
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { ChromeSafeBrowsingProtectionLevel = 2 }));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void SafeBrowsing_EdgeSmartScreenZero_IsCritical()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { EdgeSmartScreenEnabled = 0 }));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("Edge SmartScreen Disabled", f.Title);
    }

    [Fact]
    public void SafeBrowsing_WindowsOff_IsWarning()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { WindowsSmartScreen = "Off" }));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Windows SmartScreen Disabled", f.Title);
    }

    [Fact]
    public void SafeBrowsing_WindowsWarn_IsNotFlagged()
    {
        var f = Assert.Single(AnalyzeSafeBrowsing(new BrowserPolicyState { WindowsSmartScreen = "Warn" }));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void SafeBrowsing_AllDisabled_YieldsThreeFindings_NoPass()
    {
        var findings = AnalyzeSafeBrowsing(new BrowserPolicyState
        {
            ChromeSafeBrowsingProtectionLevel = 0,
            EdgeSmartScreenEnabled = 0,
            WindowsSmartScreen = "Off",
        });
        Assert.Equal(3, findings.Count);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
        Assert.Equal(2, findings.Count(f => f.Severity == Severity.Critical));
        Assert.Equal(1, findings.Count(f => f.Severity == Severity.Warning));
    }

    // ------------------------------------------------------------------
    // Saved passwords
    // ------------------------------------------------------------------

    [Fact]
    public void SavedPasswords_NoFiles_IsPass()
    {
        var f = BuildSavedPasswordFinding(new SavedPasswordState());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("No Browser Saved Passwords Detected", f.Title);
    }

    [Fact]
    public void SavedPasswords_SmallChromeDb_IsPass()
    {
        // Below threshold (empty ~40KB DB).
        var f = BuildSavedPasswordFinding(new SavedPasswordState { ChromeLoginDataBytes = 40000 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void SavedPasswords_LargeChromeDb_IsWarning()
    {
        var f = BuildSavedPasswordFinding(new SavedPasswordState { ChromeLoginDataBytes = 60000 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Saved Passwords in Browser", f.Title);
        Assert.Contains("Chrome", f.Description);
        Assert.DoesNotContain("Edge", f.Description);
    }

    [Fact]
    public void SavedPasswords_BothBrowsers_ListsBoth()
    {
        var f = BuildSavedPasswordFinding(new SavedPasswordState { ChromeLoginDataBytes = 60000, EdgeLoginDataBytes = 50000 });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Chrome and Edge", f.Description);
    }

    [Fact]
    public void SavedPasswords_ExactlyThreshold_IsPass()
    {
        // Strictly greater-than threshold, so == threshold is not flagged.
        var f = BuildSavedPasswordFinding(new SavedPasswordState { ChromeLoginDataBytes = SavedPasswordSizeThreshold });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // ------------------------------------------------------------------
    // Popup blocker
    // ------------------------------------------------------------------

    [Fact]
    public void Popups_NoPolicies_IsPass()
    {
        var f = Assert.Single(AnalyzePopupBlocker(new BrowserPolicyState()));
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Popup Blockers Active", f.Title);
    }

    [Fact]
    public void Popups_ChromeAllowAll_IsWarning()
    {
        var f = Assert.Single(AnalyzePopupBlocker(new BrowserPolicyState { ChromeDefaultPopupsSetting = 1 }));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Chrome Popup Blocker Disabled", f.Title);
    }

    [Fact]
    public void Popups_ChromeBlockAll_IsNotFlagged()
    {
        // 2 = block all popups (good).
        var f = Assert.Single(AnalyzePopupBlocker(new BrowserPolicyState { ChromeDefaultPopupsSetting = 2 }));
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Popups_EdgeAllowAll_IsWarning()
    {
        var f = Assert.Single(AnalyzePopupBlocker(new BrowserPolicyState { EdgeDefaultPopupsSetting = 1 }));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal("Edge Popup Blocker Disabled", f.Title);
    }

    [Fact]
    public void Popups_BothAllowAll_YieldsTwoWarnings_NoPass()
    {
        var findings = AnalyzePopupBlocker(new BrowserPolicyState { ChromeDefaultPopupsSetting = 1, EdgeDefaultPopupsSetting = 1 });
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Warning, f.Severity));
    }

    // ------------------------------------------------------------------
    // Tracking protection
    // ------------------------------------------------------------------

    [Fact]
    public void Tracking_NoPolicies_IsInfo()
    {
        var f = BuildTrackingProtectionFinding(new BrowserPolicyState());
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Equal("Do Not Track / Tracking Prevention", f.Title);
    }

    [Fact]
    public void Tracking_EdgeDntOn_IsPass()
    {
        var f = BuildTrackingProtectionFinding(new BrowserPolicyState { EdgeConfigureDoNotTrack = 1 });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("Tracking Protection Enabled", f.Title);
    }

    [Fact]
    public void Tracking_EdgePreventionBalanced_IsPass()
    {
        // 2 = balanced (meaningful). 1 = basic is not enough.
        var f = BuildTrackingProtectionFinding(new BrowserPolicyState { EdgeTrackingPrevention = 2 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void Tracking_EdgePreventionBasic_IsNotEnough()
    {
        var f = BuildTrackingProtectionFinding(new BrowserPolicyState { EdgeTrackingPrevention = 1 });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public void Tracking_EdgePreventionStrict_IsPass()
    {
        var f = BuildTrackingProtectionFinding(new BrowserPolicyState { EdgeTrackingPrevention = 3 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    // ------------------------------------------------------------------
    // Security policies (hardening)
    // ------------------------------------------------------------------

    [Fact]
    public void SecurityPolicies_NoPolicies_YieldsNoFindings()
    {
        // These are advisory hardening checks; absence means nothing to report.
        Assert.Empty(AnalyzeSecurityPolicies(new BrowserPolicyState()));
    }

    [Fact]
    public void SecurityPolicies_ChromeJavaScriptBlocked_IsInfo()
    {
        // JS-blocked is reported as Info (improves security but breaks many sites).
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { ChromeDefaultJavaScriptSetting = 2 });
        Assert.Contains(findings, f => f.Severity == Severity.Info && f.Title.Contains("JavaScript"));
    }

    [Fact]
    public void SecurityPolicies_ChromePasswordManagerDisabled_IsPass()
    {
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { ChromePasswordManagerEnabled = 0 });
        Assert.Contains(findings, f => f.Severity == Severity.Pass && f.Title.Contains("Chrome") && f.Title.Contains("Password Manager"));
    }

    [Fact]
    public void SecurityPolicies_EdgePasswordManagerDisabled_IsPass()
    {
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { EdgePasswordManagerEnabled = 0 });
        Assert.Contains(findings, f => f.Severity == Severity.Pass && f.Title.Contains("Edge") && f.Title.Contains("Password Manager"));
    }

    [Fact]
    public void SecurityPolicies_ChromeSitePerProcessEnforced_IsPass()
    {
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { ChromeSitePerProcess = 1 });
        Assert.Contains(findings, f => f.Severity == Severity.Pass && f.Title.Contains("Site Isolation"));
    }

    [Fact]
    public void SecurityPolicies_ChromeDownloadRestrictionsActive_IsPass()
    {
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { ChromeDownloadRestrictions = 1 });
        Assert.Contains(findings, f => f.Severity == Severity.Pass && f.Title.Contains("Download"));
    }

    [Fact]
    public void SecurityPolicies_DownloadRestrictionsZero_NotReported()
    {
        // 0 = no restriction; only >=1 is an active hardening worth a Pass.
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState { ChromeDownloadRestrictions = 0 });
        Assert.DoesNotContain(findings, f => f.Title.Contains("Download"));
    }

    [Fact]
    public void SecurityPolicies_AllHardenings_YieldMultiplePasses()
    {
        var findings = AnalyzeSecurityPolicies(new BrowserPolicyState
        {
            ChromePasswordManagerEnabled = 0,
            ChromeSitePerProcess = 1,
            ChromeDownloadRestrictions = 2,
        });
        Assert.True(findings.Count >= 3);
        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
    }

    // ------------------------------------------------------------------
    // Cross-cutting: every emitted Critical/Warning honors Finding invariants
    // ------------------------------------------------------------------

    [Fact]
    public void AllBranches_CriticalAndWarningFindings_HaveRequiredRemediation()
    {
        var all = new List<Finding>();
        all.Add(BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Chrome, Installed = true, RawVersion = "1.0.0.0" }));
        all.Add(BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Edge, Installed = true, RawVersion = "1.0.0.0" }));
        all.Add(BuildVersionFinding(new BrowserVersionState { Kind = BrowserKind.Firefox, Installed = true, RawVersion = "1.0" }));
        all.AddRange(AnalyzeExtensions(new[] { Ext(DangerousExtensionIds.First(), "Bad"), Ext("g", "G", "proxy") }));
        all.AddRange(AnalyzeAutoUpdate(new BrowserPolicyState { ChromeUpdateDefault = 0, EdgeUpdateDefault = 0 }));
        all.AddRange(AnalyzeSafeBrowsing(new BrowserPolicyState { ChromeSafeBrowsingProtectionLevel = 0, EdgeSmartScreenEnabled = 0, WindowsSmartScreen = "Off" }));
        all.Add(BuildSavedPasswordFinding(new SavedPasswordState { ChromeLoginDataBytes = 60000 }));
        all.AddRange(AnalyzePopupBlocker(new BrowserPolicyState { ChromeDefaultPopupsSetting = 1, EdgeDefaultPopupsSetting = 1 }));

        foreach (var f in all.Where(f => f.Severity == Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Remediation), $"Critical '{f.Title}' missing remediation");
            Assert.False(string.IsNullOrWhiteSpace(f.FixCommand), $"Critical '{f.Title}' missing fix command");
        }
        foreach (var f in all.Where(f => f.Severity == Severity.Warning))
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Remediation), $"Warning '{f.Title}' missing remediation");
        }

        Assert.All(all, f => Assert.Equal("Browser", f.Category));
    }
}
