using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using State = WinSentinel.Core.Audits.IdentityCredentialAnalyzer.IdentityState;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="IdentityCredentialAnalyzer"/> — the pure, I/O-free
/// credential-hygiene decision logic behind the <see cref="IdentityCredentialAudit"/>
/// module. Previously these thresholds lived inline inside the registry/PowerShell
/// collection methods and could only be exercised by integration tests that asserted
/// "a finding exists", never the actual classification.
///
/// These tests pin every security-relevant boundary directly with synthetic state:
/// well-known vs. risky never-expire accounts, the admin-sprawl threshold, the
/// cached-logon thresholds, LSA Protection, the Credential Guard VBS/LsaCfgFlags
/// matrix, LAPS posture (standalone / Windows / legacy / not-deployed), and the JSON
/// name parser. All deterministic — no shell, no registry, no clock.
/// </summary>
public class IdentityCredentialAnalyzerTests
{
    private const string Cat = "Identity";

    // ----------------------------------------------------------------------
    // ExtractJsonNames
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("null")]
    [InlineData("NULL")]
    public void ExtractJsonNames_NullOrBlank_Empty(string? input)
    {
        Assert.Empty(IdentityCredentialAnalyzer.ExtractJsonNames(input));
    }

    [Fact]
    public void ExtractJsonNames_SingleObject_ReturnsOneName()
    {
        var names = IdentityCredentialAnalyzer.ExtractJsonNames(
            "{\"Name\":\"svc_backup\",\"LastLogon\":null}");
        Assert.Equal(new[] { "svc_backup" }, names);
    }

    [Fact]
    public void ExtractJsonNames_Array_ReturnsAllNamesInOrder()
    {
        var json = "[{\"Name\":\"alice\",\"LastLogon\":null}," +
                   "{\"Name\":\"svc_sql\",\"LastLogon\":null}," +
                   "{\"Name\":\"Guest\",\"LastLogon\":null}]";
        var names = IdentityCredentialAnalyzer.ExtractJsonNames(json);
        Assert.Equal(new[] { "alice", "svc_sql", "Guest" }, names);
    }

    [Fact]
    public void ExtractJsonNames_IsCaseInsensitiveOnKey()
    {
        var names = IdentityCredentialAnalyzer.ExtractJsonNames("{\"name\":\"lower\"}");
        Assert.Equal(new[] { "lower" }, names);
    }

    [Fact]
    public void ExtractJsonNames_HandlesWhitespaceAfterColon()
    {
        // ConvertTo-Json -Compress never puts a space before the colon, but it may
        // appear after it; ReadJsonStringValue skips leading whitespace.
        var names = IdentityCredentialAnalyzer.ExtractJsonNames("{\"Name\":  \"spaced\"}");
        Assert.Equal(new[] { "spaced" }, names);
    }

    [Fact]
    public void ExtractJsonNames_NoNameKey_Empty()
    {
        Assert.Empty(IdentityCredentialAnalyzer.ExtractJsonNames("{\"Other\":\"x\"}"));
    }

    [Fact]
    public void ExtractJsonNames_EscapedQuoteInValue_DoesNotTerminateEarly()
    {
        // Name literally contains an escaped quote: a"b
        var names = IdentityCredentialAnalyzer.ExtractJsonNames("{\"Name\":\"a\\\"b\"}");
        Assert.Single(names);
        Assert.Equal("a\"b", names[0]);
    }

    // ----------------------------------------------------------------------
    // FilterRiskyNeverExpireAccounts
    // ----------------------------------------------------------------------

    [Fact]
    public void FilterRisky_DropsAllWellKnownAccounts()
    {
        var risky = IdentityCredentialAnalyzer.FilterRiskyNeverExpireAccounts(
            new[] { "DefaultAccount", "WDAGUtilityAccount", "Guest" });
        Assert.Empty(risky);
    }

    [Fact]
    public void FilterRisky_WellKnownMatchIsCaseInsensitive()
    {
        var risky = IdentityCredentialAnalyzer.FilterRiskyNeverExpireAccounts(
            new[] { "guest", "DEFAULTACCOUNT" });
        Assert.Empty(risky);
    }

    [Fact]
    public void FilterRisky_KeepsRealAccounts_PreservesOrder()
    {
        var risky = IdentityCredentialAnalyzer.FilterRiskyNeverExpireAccounts(
            new[] { "svc_a", "Guest", "Administrator", "svc_b" });
        Assert.Equal(new[] { "svc_a", "Administrator", "svc_b" }, risky);
    }

    [Fact]
    public void FilterRisky_TrimsAndDropsBlanks()
    {
        var risky = IdentityCredentialAnalyzer.FilterRiskyNeverExpireAccounts(
            new[] { "  svc_x  ", "", "   ", "Guest" });
        Assert.Equal(new[] { "svc_x" }, risky);
    }

    [Fact]
    public void FilterRisky_Null_Empty()
    {
        Assert.Empty(IdentityCredentialAnalyzer.FilterRiskyNeverExpireAccounts(null));
    }

    // ----------------------------------------------------------------------
    // BuildPasswordNeverExpiresFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void Password_CheckFailed_Skipped()
    {
        var f = IdentityCredentialAnalyzer.BuildPasswordNeverExpiresFinding(
            new State { PasswordExpiryCheckFailed = true });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Skipped", f.Title);
        Assert.Equal(Cat, f.Category);
    }

    [Fact]
    public void Password_NoCandidates_PassAllConfigured()
    {
        var f = IdentityCredentialAnalyzer.BuildPasswordNeverExpiresFinding(new State());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("All enabled local accounts", f.Description);
    }

    [Fact]
    public void Password_OnlyWellKnown_PassNoRisky()
    {
        var f = IdentityCredentialAnalyzer.BuildPasswordNeverExpiresFinding(
            new State { NeverExpireAccountNames = new() { "Guest", "DefaultAccount" } });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("well-known system accounts", f.Description);
    }

    [Fact]
    public void Password_RiskyAccounts_WarnsWithNamesAndFix()
    {
        var f = IdentityCredentialAnalyzer.BuildPasswordNeverExpiresFinding(
            new State { NeverExpireAccountNames = new() { "svc_sql", "Guest", "svc_iis" } });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("2 accounts", f.Title);            // plural, Guest excluded
        Assert.Contains("svc_sql", f.Description);
        Assert.Contains("svc_iis", f.Description);
        Assert.DoesNotContain("Guest", f.Description);
        Assert.Contains("svc_sql", f.FixCommand);          // fix targets first risky
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation));
    }

    [Fact]
    public void Password_SingleRiskyAccount_UsesSingularNoun()
    {
        var f = IdentityCredentialAnalyzer.BuildPasswordNeverExpiresFinding(
            new State { NeverExpireAccountNames = new() { "svc_only" } });
        Assert.Contains("1 account)", f.Title);
        Assert.DoesNotContain("accounts", f.Title);
    }

    // ----------------------------------------------------------------------
    // BuildStaleAccountsFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void Stale_CheckFailed_Skipped()
    {
        var f = IdentityCredentialAnalyzer.BuildStaleAccountsFinding(
            new State { StaleAccountCheckFailed = true });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Skipped", f.Title);
    }

    [Fact]
    public void Stale_None_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildStaleAccountsFinding(new State());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("90 days", f.Description);
    }

    [Fact]
    public void Stale_Some_WarnsWithCountAndFix()
    {
        var f = IdentityCredentialAnalyzer.BuildStaleAccountsFinding(
            new State { StaleAccountNames = new() { "olduser", "tempadmin" } });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("(2)", f.Title);
        Assert.Contains("olduser", f.Description);
        Assert.Contains("Disable-LocalUser -Name 'olduser'", f.FixCommand);
    }

    [Fact]
    public void Stale_DropsBlankEntries()
    {
        var f = IdentityCredentialAnalyzer.BuildStaleAccountsFinding(
            new State { StaleAccountNames = new() { "real", "  ", "" } });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("(1)", f.Title);
    }

    // ----------------------------------------------------------------------
    // BuildAdminSprawlFindings
    // ----------------------------------------------------------------------

    [Fact]
    public void AdminSprawl_NotReadable_NoFindings()
    {
        var findings = IdentityCredentialAnalyzer.BuildAdminSprawlFindings(
            new State { AdminGroupReadable = false, AdminMemberCount = 99 });
        Assert.Empty(findings);
    }

    [Fact]
    public void AdminSprawl_AtThreshold_NoWarning()
    {
        // Threshold is 3 — exactly 3 members is tolerated.
        var findings = IdentityCredentialAnalyzer.BuildAdminSprawlFindings(
            new State { AdminGroupReadable = true, AdminMemberCount = 3 });
        Assert.Empty(findings);
    }

    [Fact]
    public void AdminSprawl_AboveThreshold_Warns()
    {
        var findings = IdentityCredentialAnalyzer.BuildAdminSprawlFindings(
            new State { AdminGroupReadable = true, AdminMemberCount = 4 });
        var warn = Assert.Single(findings);
        Assert.Equal(Severity.Warning, warn.Severity);
        Assert.Contains("4 members", warn.Title);
    }

    [Fact]
    public void AdminSprawl_NestedGroups_AddsInfo()
    {
        var findings = IdentityCredentialAnalyzer.BuildAdminSprawlFindings(
            new State { AdminGroupReadable = true, AdminMemberCount = 2, AdminGroupHasNestedGroups = true });
        var info = Assert.Single(findings);
        Assert.Equal(Severity.Info, info.Severity);
        Assert.Contains("Nested Groups", info.Title);
    }

    [Fact]
    public void AdminSprawl_SprawlAndNested_TwoFindings()
    {
        var findings = IdentityCredentialAnalyzer.BuildAdminSprawlFindings(
            new State { AdminGroupReadable = true, AdminMemberCount = 7, AdminGroupHasNestedGroups = true });
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
        Assert.Contains(findings, f => f.Severity == Severity.Info);
    }

    // ----------------------------------------------------------------------
    // BuildCachedCredentialsFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void Cached_NotConfigured_InfoDefaultTen()
    {
        var f = IdentityCredentialAnalyzer.BuildCachedCredentialsFinding(
            new State { CachedLogonsConfigured = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Default (10)", f.Title);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(4)]
    public void Cached_AtOrBelowMax_Pass(int count)
    {
        var f = IdentityCredentialAnalyzer.BuildCachedCredentialsFinding(
            new State { CachedLogonsConfigured = true, CachedLogonsCount = count });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains($"Cached Credentials: {count}", f.Title);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(10)]
    [InlineData(50)]
    public void Cached_AboveMax_Warns(int count)
    {
        var f = IdentityCredentialAnalyzer.BuildCachedCredentialsFinding(
            new State { CachedLogonsConfigured = true, CachedLogonsCount = count });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains($"({count})", f.Title);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Cached_BoundaryFourVsFive()
    {
        var pass = IdentityCredentialAnalyzer.BuildCachedCredentialsFinding(
            new State { CachedLogonsConfigured = true, CachedLogonsCount = 4 });
        var warn = IdentityCredentialAnalyzer.BuildCachedCredentialsFinding(
            new State { CachedLogonsConfigured = true, CachedLogonsCount = 5 });
        Assert.Equal(Severity.Pass, pass.Severity);
        Assert.Equal(Severity.Warning, warn.Severity);
    }

    // ----------------------------------------------------------------------
    // BuildLsaProtectionFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void Lsa_KeyUnreadable_Null()
    {
        Assert.Null(IdentityCredentialAnalyzer.BuildLsaProtectionFinding(
            new State { LsaKeyReadable = false }));
    }

    [Fact]
    public void Lsa_Enabled_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildLsaProtectionFinding(
            new State { LsaKeyReadable = true, RunAsPplEnabled = true });
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("LSA Protection Enabled", f.Title);
    }

    [Fact]
    public void Lsa_EnabledRegistryOnly_PassSuggestsUefiLock()
    {
        // RunAsPPL = 1: enabled but not UEFI-locked. Still a Pass, but should
        // nudge toward value 2 with a concrete fix.
        var f = IdentityCredentialAnalyzer.BuildLsaProtectionFinding(
            new State { LsaKeyReadable = true, RunAsPplEnabled = true, RunAsPplUefiLocked = false });
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.DoesNotContain("UEFI-Locked", f.Title);
        Assert.Contains("RunAsPPL", f.FixCommand);
        Assert.Contains("1", f.FixCommand);
    }

    [Fact]
    public void Lsa_UefiLocked_PassNoFixNeeded()
    {
        // RunAsPPL = 2: the most hardened setting. Previously mis-reported as a
        // Warning because the collector only matched `== 1`.
        var f = IdentityCredentialAnalyzer.BuildLsaProtectionFinding(
            new State { LsaKeyReadable = true, RunAsPplEnabled = true, RunAsPplUefiLocked = true });
        Assert.NotNull(f);
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("UEFI-Locked", f.Title);
    }

    [Fact]
    public void Lsa_Disabled_WarnsWithFix()
    {
        var f = IdentityCredentialAnalyzer.BuildLsaProtectionFinding(
            new State { LsaKeyReadable = true, RunAsPplEnabled = false });
        Assert.NotNull(f);
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("RunAsPPL", f.FixCommand);
    }

    // ----------------------------------------------------------------------
    // BuildCredentialGuardFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void CredGuard_NoDeviceGuardKey_NotConfigured()
    {
        var f = IdentityCredentialAnalyzer.BuildCredentialGuardFinding(
            new State { DeviceGuardKeyPresent = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Configured", f.Title);
    }

    [Fact]
    public void CredGuard_VbsAndLsaCfg_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildCredentialGuardFinding(
            new State { DeviceGuardKeyPresent = true, VbsEnabled = true, LsaCfgFlags = 1 });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Credential Guard Enabled", f.Title);
    }

    [Fact]
    public void CredGuard_VbsWithoutLockFlagTwo_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildCredentialGuardFinding(
            new State { DeviceGuardKeyPresent = true, VbsEnabled = true, LsaCfgFlags = 2 });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void CredGuard_VbsOnly_PartiallyConfiguredInfo()
    {
        var f = IdentityCredentialAnalyzer.BuildCredentialGuardFinding(
            new State { DeviceGuardKeyPresent = true, VbsEnabled = true, LsaCfgFlags = 0 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Fully Configured", f.Title);
    }

    [Fact]
    public void CredGuard_KeyPresentButVbsOff_NotEnabledInfo()
    {
        var f = IdentityCredentialAnalyzer.BuildCredentialGuardFinding(
            new State { DeviceGuardKeyPresent = true, VbsEnabled = false, LsaCfgFlags = 1 });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Enabled", f.Title);
    }

    // ----------------------------------------------------------------------
    // BuildLapsFinding
    // ----------------------------------------------------------------------

    [Fact]
    public void Laps_CheckFailed_Skipped()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(new State { LapsCheckFailed = true });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Skipped", f.Title);
    }

    [Fact]
    public void Laps_Standalone_NotApplicable()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(new State { IsDomainJoined = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Standalone", f.Title);
    }

    [Fact]
    public void Laps_DomainWindowsLaps_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(
            new State { IsDomainJoined = true, WindowsLapsActive = true });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Windows LAPS Active", f.Title);
    }

    [Fact]
    public void Laps_DomainLegacyLaps_Pass()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(
            new State { IsDomainJoined = true, LegacyLapsInstalled = true });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Legacy LAPS", f.Title);
    }

    [Fact]
    public void Laps_WindowsLapsTakesPrecedenceOverLegacy()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(
            new State { IsDomainJoined = true, WindowsLapsActive = true, LegacyLapsInstalled = true });
        Assert.Contains("Windows LAPS Active", f.Title);
    }

    [Fact]
    public void Laps_DomainNoLaps_Warns()
    {
        var f = IdentityCredentialAnalyzer.BuildLapsFinding(new State { IsDomainJoined = true });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("LAPS Not Deployed", f.Title);
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation));
    }

    // ----------------------------------------------------------------------
    // BuildFindings (orchestration / ordering / category)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildFindings_CleanStandaloneMachine_AllPresentAndCategorised()
    {
        // A fully-collected, healthy standalone workstation.
        var state = new State
        {
            AdminGroupReadable = true,
            AdminMemberCount = 2,
            IsDomainJoined = false,
            CachedLogonsConfigured = true,
            CachedLogonsCount = 2,
            LsaKeyReadable = true,
            RunAsPplEnabled = true,
            DeviceGuardKeyPresent = true,
            VbsEnabled = true,
            LsaCfgFlags = 1
        };

        var findings = IdentityCredentialAnalyzer.BuildFindings(state);

        // password + stale + (no sprawl) + laps + cached + lsa + credguard = 6
        Assert.Equal(6, findings.Count);
        Assert.All(findings, f => Assert.Equal(Cat, f.Category));
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Title)));
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Description)));

        // Healthy machine → no warnings or criticals.
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void BuildFindings_AdminSprawlAddsExtraFinding()
    {
        var baseState = new State
        {
            AdminGroupReadable = true,
            AdminMemberCount = 2,
            CachedLogonsConfigured = true,
            CachedLogonsCount = 2,
            LsaKeyReadable = true,
            RunAsPplEnabled = true,
            DeviceGuardKeyPresent = true
        };
        var sprawlState = new State
        {
            AdminGroupReadable = true,
            AdminMemberCount = 9,            // sprawl
            CachedLogonsConfigured = true,
            CachedLogonsCount = 2,
            LsaKeyReadable = true,
            RunAsPplEnabled = true,
            DeviceGuardKeyPresent = true
        };

        var baseCount = IdentityCredentialAnalyzer.BuildFindings(baseState).Count;
        var sprawl = IdentityCredentialAnalyzer.BuildFindings(sprawlState);

        // Sprawl introduces exactly one extra finding.
        Assert.Equal(baseCount + 1, sprawl.Count);
        Assert.Contains(sprawl, f => f.Title.Contains("Admin Sprawl") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void BuildFindings_LsaUnreadable_OmitsLsaFinding()
    {
        var state = new State
        {
            AdminGroupReadable = true,
            AdminMemberCount = 1,
            CachedLogonsConfigured = true,
            CachedLogonsCount = 1,
            LsaKeyReadable = false,           // LSA finding suppressed
            DeviceGuardKeyPresent = true
        };

        var findings = IdentityCredentialAnalyzer.BuildFindings(state);
        Assert.DoesNotContain(findings, f => f.Title.Contains("LSA Protection"));
    }

    [Fact]
    public void BuildFindings_FullyDegradedCollection_StillProducesFindings()
    {
        // Every probe failed / unreadable: the analyzer must not throw and must
        // still emit the informational "skipped"/"not configured" findings.
        var state = new State
        {
            PasswordExpiryCheckFailed = true,
            StaleAccountCheckFailed = true,
            AdminGroupReadable = false,
            LapsCheckFailed = true,
            CachedLogonsConfigured = false,
            LsaKeyReadable = false,
            DeviceGuardKeyPresent = false
        };

        var findings = IdentityCredentialAnalyzer.BuildFindings(state);

        // password + stale + laps + cached + credguard (no sprawl, no lsa) = 5
        Assert.Equal(5, findings.Count);
        Assert.All(findings, f => Assert.Equal(Cat, f.Category));
        // Nothing should be a false-positive warning when we simply couldn't read.
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void BuildFindings_RiskyDomainMachine_SurfacesAllWarnings()
    {
        var state = new State
        {
            NeverExpireAccountNames = new() { "svc_legacy" },   // risky
            StaleAccountNames = new() { "ex_employee" },         // stale
            AdminGroupReadable = true,
            AdminMemberCount = 8,                                // sprawl
            IsDomainJoined = true,                               // + no LAPS → warn
            CachedLogonsConfigured = true,
            CachedLogonsCount = 10,                              // high
            LsaKeyReadable = true,
            RunAsPplEnabled = false,                             // LSA off → warn
            DeviceGuardKeyPresent = true,
            VbsEnabled = false
        };

        var findings = IdentityCredentialAnalyzer.BuildFindings(state);
        var warnings = findings.Where(f => f.Severity == Severity.Warning).ToList();

        // password, stale, sprawl, LAPS, cached, LSA = 6 distinct warnings.
        Assert.Equal(6, warnings.Count);
        // Every warning carries actionable remediation or a fix command.
        Assert.All(warnings, w => Assert.True(
            !string.IsNullOrWhiteSpace(w.Remediation) || !string.IsNullOrWhiteSpace(w.FixCommand)));
    }
}
