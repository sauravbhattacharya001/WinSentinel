using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.RegistryAudit;

namespace WinSentinel.Tests.Audits;

public class RegistryAuditTests
{
    private readonly RegistryAudit _audit;

    public RegistryAuditTests()
    {
        _audit = new RegistryAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Registry Security Audit",
        Category = "Registry"
    };

    private static RegistryState MakeSecureState() => new()
    {
        EnableLua = 1,
        ConsentPromptBehaviorAdmin = 2,
        EnableVirtualization = 1,
        DenyTsConnections = 1,
        NoDriveTypeAutoRun = 0xFF,
        DisableAutoplay = 1,
        CachedLogonsCount = "2",
        WDigestUseLogonCredential = 0,
        LsassRunAsPpl = 1,
        ScriptHostEnabled = "0",
        WinRmAllowAutoConfig = null,
        SafeDllSearchMode = 1,
        LoadAppInitDlls = 0,
        AppInitDlls = new List<string>(),
        IfeoDebuggers = new List<IfeoEntry>(),
        WinlogonShell = "explorer.exe",
        WinlogonUserinit = @"C:\Windows\system32\userinit.exe,",
    };

    private static RegistryState MakeInsecureState() => new()
    {
        EnableLua = 0,
        ConsentPromptBehaviorAdmin = 0,
        EnableVirtualization = 0,
        DenyTsConnections = 0,
        NlaRequired = 0,
        RdpSecurityLayer = 0,
        NoDriveTypeAutoRun = 0x91,
        DisableAutoplay = 0,
        CachedLogonsCount = "10",
        WDigestUseLogonCredential = 1,
        LsassRunAsPpl = 0,
        ScriptHostEnabled = "1",
        WinRmAllowAutoConfig = 1,
        WinRmAllowUnencrypted = 1,
        WinRmAllowBasic = 1,
        SafeDllSearchMode = 0,
        LoadAppInitDlls = 1,
        AppInitDlls = new List<string> { @"C:\malware\inject.dll" },
        IfeoDebuggers = new List<IfeoEntry>
        {
            new() { TargetExecutable = "sethc.exe", DebuggerValue = @"C:\backdoor.exe" },
            new() { TargetExecutable = "notepad.exe", DebuggerValue = @"C:\debug\dbg.exe" }
        },
        WinlogonShell = @"C:\trojan\shell.exe",
        WinlogonUserinit = @"C:\trojan\init.exe,userinit.exe",
    };

    // Module metadata

    [Fact]
    public void Name_ReturnsRegistrySecurityAudit()
    {
        Assert.Equal("Registry Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsRegistry()
    {
        Assert.Equal("Registry", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // Secure state produces all Pass/Info

    [Fact]
    public void AnalyzeState_SecureState_NoCriticalOrWarning()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeSecureState(), result);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_SecureState_HasPassFindings()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeSecureState(), result);
        Assert.True(result.Findings.Count(f => f.Severity == Severity.Pass) >= 8);
    }

    // Insecure state produces many findings

    [Fact]
    public void AnalyzeState_InsecureState_HasCriticalFindings()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.CriticalCount >= 5, $"Expected >=5 critical, got {result.CriticalCount}");
    }

    [Fact]
    public void AnalyzeState_InsecureState_HasWarningFindings()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.WarningCount >= 3, $"Expected >=3 warnings, got {result.WarningCount}");
    }

    // UAC checks

    [Fact]
    public void UacDisabled_IsCritical()
    {
        var state = MakeSecureState();
        state.EnableLua = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("UAC Disabled"));
    }

    [Fact]
    public void UacEnabled_IsPass()
    {
        var state = MakeSecureState();
        state.EnableLua = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("UAC Enabled"));
    }

    [Fact]
    public void UacAutoElevate_IsCritical()
    {
        var state = MakeSecureState();
        state.ConsentPromptBehaviorAdmin = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Auto-Elevate"));
    }

    [Fact]
    public void UacPromptOnRegularDesktop_IsWarning()
    {
        var state = MakeSecureState();
        state.ConsentPromptBehaviorAdmin = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Regular Desktop"));
    }

    [Fact]
    public void UacSecureDesktop_IsPass()
    {
        var state = MakeSecureState();
        state.ConsentPromptBehaviorAdmin = 5;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Prompt Behavior Secure"));
    }

    [Fact]
    public void VirtualizationDisabled_IsWarning()
    {
        var state = MakeSecureState();
        state.EnableVirtualization = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Virtualization Disabled"));
    }

    // Remote Desktop checks

    [Fact]
    public void RdpDisabled_IsPass()
    {
        var state = MakeSecureState();
        state.DenyTsConnections = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Remote Desktop Disabled"));
    }

    [Fact]
    public void RdpEnabledNoNla_IsCritical()
    {
        var state = MakeSecureState();
        state.DenyTsConnections = 0;
        state.NlaRequired = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Network Level Authentication Not Required"));
    }

    [Fact]
    public void RdpEnabledWithNla_IsPass()
    {
        var state = MakeSecureState();
        state.DenyTsConnections = 0;
        state.NlaRequired = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Network Level Authentication Required"));
    }

    [Fact]
    public void RdpLegacySecurity_IsWarning()
    {
        var state = MakeSecureState();
        state.DenyTsConnections = 0;
        state.NlaRequired = 1;
        state.RdpSecurityLayer = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Legacy Security Layer"));
    }

    // AutoPlay checks

    [Fact]
    public void AutoRunDisabled_IsPass()
    {
        var state = MakeSecureState();
        state.NoDriveTypeAutoRun = 0xFF;
        state.DisableAutoplay = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("AutoPlay/AutoRun Disabled"));
    }

    [Fact]
    public void AutoPlayDisabledAlternate_IsPass()
    {
        var state = MakeSecureState();
        state.NoDriveTypeAutoRun = null;
        state.DisableAutoplay = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("AutoPlay/AutoRun Disabled"));
    }

    [Fact]
    public void AutoRunNotDisabled_IsWarning()
    {
        var state = MakeSecureState();
        state.NoDriveTypeAutoRun = 0x91;
        state.DisableAutoplay = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Not Fully Disabled"));
    }

    // Credential checks

    [Fact]
    public void HighCachedLogons_IsWarning()
    {
        var state = MakeSecureState();
        state.CachedLogonsCount = "10";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Cached Logon Count"));
    }

    [Fact]
    public void LowCachedLogons_IsPass()
    {
        var state = MakeSecureState();
        state.CachedLogonsCount = "2";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Cached Logon Count Acceptable"));
    }

    [Fact]
    public void WDigestEnabled_IsCritical()
    {
        var state = MakeSecureState();
        state.WDigestUseLogonCredential = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("WDigest"));
    }

    [Fact]
    public void WDigestDisabled_IsPass()
    {
        var state = MakeSecureState();
        state.WDigestUseLogonCredential = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("WDigest"));
    }

    // LSASS checks

    [Fact]
    public void LsassProtected_IsPass()
    {
        var state = MakeSecureState();
        state.LsassRunAsPpl = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("LSASS Protected"));
    }

    [Fact]
    public void LsassNotProtected_IsWarning()
    {
        var state = MakeSecureState();
        state.LsassRunAsPpl = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("LSASS Not Running"));
    }

    // Script Host checks

    [Fact]
    public void ScriptHostDisabled_IsPass()
    {
        var state = MakeSecureState();
        state.ScriptHostEnabled = "0";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Script Host Disabled"));
    }

    [Fact]
    public void ScriptHostEnabled_IsInfo()
    {
        var state = MakeSecureState();
        state.ScriptHostEnabled = "1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Info && f.Title.Contains("Script Host Enabled"));
    }

    [Fact]
    public void ScriptHostNull_IsInfo()
    {
        var state = MakeSecureState();
        state.ScriptHostEnabled = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Info && f.Title.Contains("Script Host Enabled"));
    }

    // WinRM checks

    [Fact]
    public void WinRmOff_IsPass()
    {
        var state = MakeSecureState();
        state.WinRmAllowAutoConfig = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("WinRM Not Auto-Configured"));
    }

    [Fact]
    public void WinRmOnWithUnencrypted_IsCritical()
    {
        var state = MakeSecureState();
        state.WinRmAllowAutoConfig = 1;
        state.WinRmAllowUnencrypted = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Unencrypted"));
    }

    [Fact]
    public void WinRmOnWithBasicAuth_IsWarning()
    {
        var state = MakeSecureState();
        state.WinRmAllowAutoConfig = 1;
        state.WinRmAllowBasic = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("Basic Authentication"));
    }

    [Fact]
    public void WinRmEnabled_IsInfo()
    {
        var state = MakeSecureState();
        state.WinRmAllowAutoConfig = 1;
        state.WinRmAllowUnencrypted = 0;
        state.WinRmAllowBasic = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Info && f.Title.Contains("WinRM Auto-Configuration Enabled"));
    }

    // DLL Safety checks

    [Fact]
    public void DllSearchSafe_IsPass()
    {
        var state = MakeSecureState();
        state.SafeDllSearchMode = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("DLL Search Mode Enabled"));
    }

    [Fact]
    public void DllSearchUnsafe_IsWarning()
    {
        var state = MakeSecureState();
        state.SafeDllSearchMode = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("DLL Search Mode Disabled"));
    }

    // Persistence checks - AppInit_DLLs

    [Fact]
    public void AppInitDllsActive_IsCritical()
    {
        var state = MakeSecureState();
        state.LoadAppInitDlls = 1;
        state.AppInitDlls = new List<string> { @"C:\bad\inject.dll" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("AppInit_DLLs Active"));
    }

    [Fact]
    public void AppInitDllsConfiguredButNotLoaded_IsInfo()
    {
        var state = MakeSecureState();
        state.LoadAppInitDlls = 0;
        state.AppInitDlls = new List<string> { @"C:\some\lib.dll" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Info && f.Title.Contains("Not Loaded"));
    }

    [Fact]
    public void NoAppInitDlls_IsPass()
    {
        var state = MakeSecureState();
        state.LoadAppInitDlls = 0;
        state.AppInitDlls = new List<string>();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("No AppInit_DLLs"));
    }

    // Persistence checks - IFEO

    [Fact]
    public void IfeoAccessibilityHijack_IsCritical()
    {
        var state = MakeSecureState();
        state.IfeoDebuggers = new List<IfeoEntry>
        {
            new() { TargetExecutable = "sethc.exe", DebuggerValue = @"C:\cmd.exe" }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Accessibility Binary Hijacking"));
    }

    [Fact]
    public void IfeoNonAccessibility_IsWarning()
    {
        var state = MakeSecureState();
        state.IfeoDebuggers = new List<IfeoEntry>
        {
            new() { TargetExecutable = "myapp.exe", DebuggerValue = @"C:\debugger.exe" }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("IFEO Debuggers Found"));
    }

    [Fact]
    public void NoIfeoDebuggers_IsPass()
    {
        var state = MakeSecureState();
        state.IfeoDebuggers = new List<IfeoEntry>();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("No IFEO"));
    }

    [Fact]
    public void IfeoEmptyDebuggerValue_Ignored()
    {
        var state = MakeSecureState();
        state.IfeoDebuggers = new List<IfeoEntry>
        {
            new() { TargetExecutable = "test.exe", DebuggerValue = "" }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("No IFEO"));
    }

    [Fact]
    public void MultipleIfeoTypes_BothReported()
    {
        var state = MakeSecureState();
        state.IfeoDebuggers = new List<IfeoEntry>
        {
            new() { TargetExecutable = "utilman.exe", DebuggerValue = @"C:\hack.exe" },
            new() { TargetExecutable = "custom.exe", DebuggerValue = @"C:\dbg.exe" }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Accessibility"));
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("IFEO Debuggers Found"));
    }

    // Persistence checks - Winlogon

    [Fact]
    public void NonStandardShell_IsCritical()
    {
        var state = MakeSecureState();
        state.WinlogonShell = @"C:\trojan\evil.exe";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Non-Standard Winlogon Shell"));
    }

    [Fact]
    public void StandardShell_NoFinding()
    {
        var state = MakeSecureState();
        state.WinlogonShell = "explorer.exe";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Non-Standard Winlogon Shell"));
    }

    [Fact]
    public void NonStandardUserinit_IsCritical()
    {
        var state = MakeSecureState();
        state.WinlogonUserinit = @"C:\malware\init.exe,";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Non-Standard Winlogon Userinit"));
    }

    [Fact]
    public void StandardUserinit_NoFinding()
    {
        var state = MakeSecureState();
        state.WinlogonUserinit = @"C:\Windows\system32\userinit.exe,";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Non-Standard Winlogon Userinit"));
    }

    // Remediation commands present

    [Fact]
    public void UacDisabled_HasFixCommand()
    {
        var state = MakeSecureState();
        state.EnableLua = 0;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("UAC Disabled"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void WDigestEnabled_HasFixCommand()
    {
        var state = MakeSecureState();
        state.WDigestUseLogonCredential = 1;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("WDigest"));
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    // Category consistency

    [Fact]
    public void AllFindings_HaveCategoryPrefix()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeInsecureState(), result);
        Assert.All(result.Findings, f => Assert.StartsWith("Registry", f.Category));
    }

    // Edge cases

    [Fact]
    public void NullState_ProducesFindings()
    {
        var state = new RegistryState(); // all defaults / nulls
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public void CachedLogonsNonNumeric_NoException()
    {
        var state = MakeSecureState();
        state.CachedLogonsCount = "abc";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        // Should not throw, just skip the check
        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public void MultipleAppInitDlls_AllListed()
    {
        var state = MakeSecureState();
        state.LoadAppInitDlls = 1;
        state.AppInitDlls = new List<string> { "a.dll", "b.dll", "c.dll" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("AppInit_DLLs Active"));
        Assert.Contains("3 DLL(s)", finding.Description);
    }

    [Fact]
    public void RdpEnabledNullNla_IsCritical()
    {
        var state = MakeSecureState();
        state.DenyTsConnections = 0;
        state.NlaRequired = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Network Level Authentication Not Required"));
    }

    [Fact]
    public void LsassRunAsPpl2_IsPass()
    {
        var state = MakeSecureState();
        state.LsassRunAsPpl = 2;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("LSASS Protected"));
    }
}
