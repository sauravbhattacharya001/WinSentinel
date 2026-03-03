using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.PowerShellAudit;

namespace WinSentinel.Tests.Audits;

public class PowerShellAuditTests
{
    private readonly PowerShellAudit _audit;

    public PowerShellAuditTests()
    {
        _audit = new PowerShellAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "PowerShell Security Audit",
        Category = "PowerShell"
    };

    private static PowerShellState MakeSecureState() => new()
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
        WinRmRunning = false,
        InstalledVersions = new List<string> { "Windows PowerShell 5.1" },
    };

    private static PowerShellState MakeInsecureState() => new()
    {
        EffectivePolicy = "Unrestricted",
        LocalMachinePolicy = "Unrestricted",
        ScriptBlockLoggingEnabled = false,
        ModuleLoggingEnabled = false,
        TranscriptionEnabled = false,
        LanguageMode = "FullLanguage",
        V2EngineInstalled = true,
        AmsiProviderRegistered = false,
        WinRmRunning = true,
        WinRmTrustedHosts = new List<string> { "*" },
        WinRmPublicAccess = true,
        InstalledVersions = new List<string> { "Windows PowerShell 5.1", "PowerShell 7" },
    };

    // ─── Module metadata ──────────────────────────────────────────

    [Fact]
    public void Name_ReturnsPowerShellSecurityAudit()
    {
        Assert.Equal("PowerShell Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsPowerShell()
    {
        Assert.Equal("PowerShell", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ─── Secure state (all passing) ───────────────────────────────

    [Fact]
    public void AnalyzeState_SecureConfig_NoWarningsOrCritical()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_SecureConfig_HasPassFindings()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.Findings.Count(f => f.Severity == Severity.Pass) >= 5,
            "Should have at least 5 Pass findings for a fully secured system");
    }

    // ─── Insecure state (all failing) ─────────────────────────────

    [Fact]
    public void AnalyzeState_InsecureConfig_HasCriticalFindings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.Findings.Count(f => f.Severity == Severity.Critical) >= 2,
            "Should flag Unrestricted policy, missing AMSI, and wildcard TrustedHosts as critical");
    }

    [Fact]
    public void AnalyzeState_InsecureConfig_HasWarningFindings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.Findings.Count(f => f.Severity == Severity.Warning) >= 3,
            "Should flag disabled logging, v2 engine, and public WinRM as warnings");
    }

    // ─── Execution policy ─────────────────────────────────────────

    [Theory]
    [InlineData("Unrestricted")]
    [InlineData("Bypass")]
    public void ExecutionPolicy_Insecure_CreatesCritical(string policy)
    {
        var state = MakeSecureState();
        state.EffectivePolicy = policy;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Execution Policy") &&
            f.Title.Contains(policy));
    }

    [Theory]
    [InlineData("AllSigned")]
    [InlineData("RemoteSigned")]
    [InlineData("Restricted")]
    public void ExecutionPolicy_Secure_CreatesPass(string policy)
    {
        var state = MakeSecureState();
        state.EffectivePolicy = policy;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("Execution Policy") &&
            f.Title.Contains(policy));
    }

    [Fact]
    public void ExecutionPolicy_Undefined_CreatesInfo()
    {
        var state = MakeSecureState();
        state.EffectivePolicy = "Undefined";
        state.LocalMachinePolicy = "Undefined";
        state.CurrentUserPolicy = "Undefined";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Not Explicitly Set"));
    }

    [Fact]
    public void ExecutionPolicy_BypassGPO_AddsExtraWarning()
    {
        var state = MakeSecureState();
        state.EffectivePolicy = "RemoteSigned"; // effective is OK
        state.MachinePolicy = "Bypass"; // but GPO is Bypass
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("GPO Machine Policy"));
    }

    [Fact]
    public void ExecutionPolicy_Critical_IncludesFixCommand()
    {
        var state = MakeSecureState();
        state.EffectivePolicy = "Unrestricted";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Severity == Severity.Critical && f.Title.Contains("Execution Policy"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("Set-ExecutionPolicy", finding.FixCommand);
    }

    // ─── Script block logging ─────────────────────────────────────

    [Fact]
    public void ScriptBlockLogging_Disabled_CreatesWarning()
    {
        var state = MakeSecureState();
        state.ScriptBlockLoggingEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Script Block Logging Disabled"));
    }

    [Fact]
    public void ScriptBlockLogging_Enabled_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("Script Block Logging Enabled"));
    }

    [Fact]
    public void ScriptBlockLogging_Disabled_IncludesRegistryPath()
    {
        var state = MakeSecureState();
        state.ScriptBlockLoggingEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("Script Block Logging Disabled"));
        Assert.Contains("ScriptBlockLogging", finding.Remediation!);
    }

    // ─── Module logging ───────────────────────────────────────────

    [Fact]
    public void ModuleLogging_Disabled_CreatesWarning()
    {
        var state = MakeSecureState();
        state.ModuleLoggingEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Module Logging Disabled"));
    }

    [Fact]
    public void ModuleLogging_Enabled_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("Module Logging Enabled"));
    }

    // ─── Transcription ────────────────────────────────────────────

    [Fact]
    public void Transcription_Disabled_CreatesInfo()
    {
        var state = MakeSecureState();
        state.TranscriptionEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Transcription Disabled"));
    }

    [Fact]
    public void Transcription_Enabled_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("Transcription Enabled"));
    }

    [Fact]
    public void Transcription_Enabled_WithDir_MentionsOutputDir()
    {
        var state = MakeSecureState();
        state.TranscriptionOutputDir = @"D:\Logs\PS";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("Transcription Enabled"));
        Assert.Contains(@"D:\Logs\PS", finding.Description);
    }

    [Fact]
    public void Transcription_Enabled_NoDir_MentionsDefault()
    {
        var state = MakeSecureState();
        state.TranscriptionOutputDir = null;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("Transcription Enabled"));
        Assert.Contains("Documents", finding.Description);
    }

    // ─── Language mode ────────────────────────────────────────────

    [Fact]
    public void LanguageMode_Full_CreatesInfo()
    {
        var state = MakeSecureState();
        state.LanguageMode = "FullLanguage";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("FullLanguage"));
    }

    [Fact]
    public void LanguageMode_Constrained_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("ConstrainedLanguage"));
    }

    [Fact]
    public void LanguageMode_Other_CreatesInfo()
    {
        var state = MakeSecureState();
        state.LanguageMode = "RestrictedLanguage";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("RestrictedLanguage"));
    }

    // ─── PowerShell v2 engine ─────────────────────────────────────

    [Fact]
    public void V2Engine_Installed_CreatesWarning()
    {
        var state = MakeSecureState();
        state.V2EngineInstalled = true;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("v2 Engine Installed"));
    }

    [Fact]
    public void V2Engine_NotInstalled_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("v2 Engine Disabled"));
    }

    [Fact]
    public void V2Engine_Warning_MentionsDowngradeAttack()
    {
        var state = MakeSecureState();
        state.V2EngineInstalled = true;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("v2 Engine Installed"));
        Assert.Contains("downgrade", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AMSI", finding.Description);
    }

    [Fact]
    public void V2Engine_Warning_HasDisableCommand()
    {
        var state = MakeSecureState();
        state.V2EngineInstalled = true;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("v2 Engine Installed"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("Disable-WindowsOptionalFeature", finding.FixCommand);
    }

    // ─── AMSI ─────────────────────────────────────────────────────

    [Fact]
    public void Amsi_NotRegistered_CreatesCritical()
    {
        var state = MakeSecureState();
        state.AmsiProviderRegistered = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("AMSI Provider Not Registered"));
    }

    [Fact]
    public void Amsi_Registered_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("AMSI Provider Registered"));
    }

    [Fact]
    public void Amsi_NotRegistered_MentionsTampering()
    {
        var state = MakeSecureState();
        state.AmsiProviderRegistered = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f =>
            f.Title.Contains("AMSI Provider Not Registered"));
        Assert.Contains("tampering", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    // ─── WinRM / Remoting ─────────────────────────────────────────

    [Fact]
    public void WinRm_NotRunning_CreatesPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("WinRM Service Not Running"));
    }

    [Fact]
    public void WinRm_Running_CreatesInfo()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = new List<string>();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("WinRM Service Running"));
    }

    [Fact]
    public void WinRm_WildcardTrustedHosts_CreatesCritical()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = new List<string> { "*" };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Wildcard"));
    }

    [Fact]
    public void WinRm_SpecificTrustedHosts_CreatesInfo()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmTrustedHosts = new List<string> { "server1.corp.local", "server2.corp.local" };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("TrustedHosts: 2 entries"));
    }

    [Fact]
    public void WinRm_PublicAccess_CreatesWarning()
    {
        var state = MakeSecureState();
        state.WinRmRunning = true;
        state.WinRmPublicAccess = true;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Public Networks"));
    }

    [Fact]
    public void WinRm_NotRunning_SkipsTrustedHostsCheck()
    {
        var state = MakeSecureState();
        state.WinRmRunning = false;
        state.WinRmTrustedHosts = new List<string> { "*" }; // would be critical if checked
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("TrustedHosts") || f.Title.Contains("Wildcard"));
    }

    // ─── Versions ─────────────────────────────────────────────────

    [Fact]
    public void Versions_Multiple_CreatesInfoWithCount()
    {
        var state = MakeSecureState();
        state.InstalledVersions = new List<string>
        {
            "Windows PowerShell 5.1",
            "PowerShell 7.4"
        };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Versions Installed: 2"));
    }

    [Fact]
    public void Versions_Empty_NoFinding()
    {
        var state = MakeSecureState();
        state.InstalledVersions = new List<string>();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Versions Installed"));
    }

    // ─── Static data ──────────────────────────────────────────────

    [Fact]
    public void InsecurePolicies_ContainsExpected()
    {
        Assert.Contains("Unrestricted", PowerShellAudit.InsecurePolicies);
        Assert.Contains("Bypass", PowerShellAudit.InsecurePolicies);
        Assert.Equal(2, PowerShellAudit.InsecurePolicies.Count);
    }

    [Fact]
    public void SecurePolicies_ContainsExpected()
    {
        Assert.Contains("AllSigned", PowerShellAudit.SecurePolicies);
        Assert.Contains("RemoteSigned", PowerShellAudit.SecurePolicies);
        Assert.Contains("Restricted", PowerShellAudit.SecurePolicies);
    }

    [Fact]
    public void InsecurePolicies_CaseInsensitive()
    {
        Assert.Contains("unrestricted", PowerShellAudit.InsecurePolicies);
        Assert.Contains("BYPASS", PowerShellAudit.InsecurePolicies);
    }

    // ─── Combined scenarios ───────────────────────────────────────

    [Fact]
    public void AnalyzeState_AllFindingsHaveCategory()
    {
        var state = MakeInsecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.All(result.Findings, f =>
            Assert.Equal("PowerShell", f.Category));
    }

    [Fact]
    public void AnalyzeState_WarningsAndCriticals_HaveRemediation()
    {
        var state = MakeInsecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var actionable = result.Findings
            .Where(f => f.Severity == Severity.Warning || f.Severity == Severity.Critical);

        Assert.All(actionable, f =>
            Assert.False(string.IsNullOrWhiteSpace(f.Remediation),
                $"Finding '{f.Title}' should have remediation guidance"));
    }

    [Fact]
    public void AnalyzeState_ProducesMultipleFindings()
    {
        var state = MakeSecureState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        // Should produce findings for: execution policy, script block logging,
        // module logging, transcription, language mode, v2 engine, AMSI,
        // WinRM, and versions
        Assert.True(result.Findings.Count >= 8,
            $"Expected at least 8 findings but got {result.Findings.Count}");
    }

    // ─── PowerShellState defaults ─────────────────────────────────

    [Fact]
    public void PowerShellState_DefaultValues_AreReasonable()
    {
        var state = new PowerShellState();

        Assert.Equal("Undefined", state.MachinePolicy);
        Assert.Equal("Undefined", state.EffectivePolicy);
        Assert.Equal("FullLanguage", state.LanguageMode);
        Assert.False(state.ScriptBlockLoggingEnabled);
        Assert.False(state.ModuleLoggingEnabled);
        Assert.False(state.TranscriptionEnabled);
        Assert.False(state.V2EngineInstalled);
        Assert.True(state.AmsiProviderRegistered);
        Assert.False(state.WinRmRunning);
        Assert.Empty(state.WinRmTrustedHosts);
        Assert.Empty(state.InstalledVersions);
    }
}
