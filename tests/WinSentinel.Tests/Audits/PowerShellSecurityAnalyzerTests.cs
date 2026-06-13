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
}
