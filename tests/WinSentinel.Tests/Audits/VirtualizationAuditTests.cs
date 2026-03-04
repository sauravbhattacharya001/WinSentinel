using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.VirtualizationAudit;

namespace WinSentinel.Tests.Audits;

public class VirtualizationAuditTests
{
    private readonly VirtualizationAudit _audit;

    public VirtualizationAuditTests()
    {
        _audit = new VirtualizationAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Virtualization Security Audit",
        Category = "Virtualization"
    };

    private static VirtualizationState MakeSecureState() => new()
    {
        HyperVEnabled = true,
        RunningVMs = new() { "DevVM" },
        VmsWithoutCheckpoints = new(),
        VmsWithExternalSwitch = new(),
        VmsWithGuestServices = new(),
        DefaultSwitchExternalAccess = false,
        WslInstalled = true,
        WslDefaultVersion = 2,
        WslDistributions = new() { "Ubuntu" },
        WslDistrosRunningAsRoot = new(),
        WslNetworkingMirrored = false,
        WslFirewallEnabled = true,
        WslInteropEnabled = false,
        WslAppendWindowsPath = false,
        WslSystemdEnabled = false,
        SandboxEnabled = true,
        SandboxNetworkingEnabled = false,
        SandboxWritableMappedFolders = false,
        DockerRunning = true,
        DockerTcpExposed = false,
        DockerTlsVerify = true,
        DockerDefaultPrivileged = false,
        DockerRootContainers = new(),
        DockerContentTrustEnabled = true,
        DockerUserNamespacesEnabled = true,
        DockerIccEnabled = false,
        DockerExperimentalEnabled = false,
        DockerRunningContainers = 3,
        VbsRunning = true,
        CredentialGuardEnabled = true,
        CredentialGuardUefiLock = true,
        HvciEnabled = true,
        MemoryIntegrityEnabled = true,
        SecureBootEnabled = true
    };

    private static VirtualizationState MakeInsecureState() => new()
    {
        HyperVEnabled = true,
        RunningVMs = new() { "TestVM", "DevVM" },
        VmsWithoutCheckpoints = new() { "TestVM" },
        VmsWithExternalSwitch = new() { "TestVM", "DevVM" },
        VmsWithGuestServices = new() { "DevVM" },
        DefaultSwitchExternalAccess = true,
        WslInstalled = true,
        WslDefaultVersion = 1,
        WslDistributions = new() { "Ubuntu", "Debian", "Kali", "Fedora", "Arch", "Alpine" },
        WslDistrosRunningAsRoot = new() { "Kali", "Alpine" },
        WslNetworkingMirrored = true,
        WslFirewallEnabled = false,
        WslInteropEnabled = true,
        WslAppendWindowsPath = true,
        WslSystemdEnabled = true,
        WslDnsTunnelingEnabled = true,
        SandboxEnabled = true,
        SandboxNetworkingEnabled = true,
        SandboxWritableMappedFolders = true,
        SandboxMappedFolders = new() { "C:\\Users\\test\\Downloads" },
        DockerRunning = true,
        DockerTcpExposed = true,
        DockerTcpPort = 2375,
        DockerTlsVerify = false,
        DockerDefaultPrivileged = true,
        DockerRootContainers = new() { "web-app", "db" },
        DockerContentTrustEnabled = false,
        DockerUserNamespacesEnabled = false,
        DockerIccEnabled = true,
        DockerExperimentalEnabled = true,
        DockerRunningContainers = 5,
        VbsRunning = false,
        CredentialGuardEnabled = false,
        CredentialGuardUefiLock = false,
        HvciEnabled = false,
        MemoryIntegrityEnabled = false,
        SecureBootEnabled = false
    };

    // ── Module metadata ──

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Virtualization Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("Virtualization", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ── Secure state ──

    [Fact]
    public void SecureState_ProducesNoWarningsOrCriticals()
    {
        var result = MakeResult();
        AnalyzeState(MakeSecureState(), result);
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
    }

    [Fact]
    public void SecureState_HasPassFindings()
    {
        var result = MakeResult();
        AnalyzeState(MakeSecureState(), result);
        Assert.True(result.PassCount > 0);
    }

    // ── Insecure state ──

    [Fact]
    public void InsecureState_ProducesCriticalFindings()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.CriticalCount >= 2); // Docker TCP + privileged
    }

    [Fact]
    public void InsecureState_ProducesWarningFindings()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.WarningCount >= 5);
    }

    // ── Hyper-V ──

    [Fact]
    public void HyperV_Disabled_ProducesInfoOnly()
    {
        var state = new VirtualizationState { HyperVEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        var hvFindings = result.Findings.Where(f => f.Category == "Hyper-V").ToList();
        Assert.Single(hvFindings);
        Assert.Equal(Severity.Info, hvFindings[0].Severity);
    }

    [Fact]
    public void HyperV_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { HyperVEnabled = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Category == "Hyper-V" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void HyperV_RunningVMs_ReportsInfo()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            RunningVMs = new() { "VM1", "VM2" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "Running Virtual Machines" && f.Description.Contains("2"));
    }

    [Fact]
    public void HyperV_NoCheckpoints_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            VmsWithoutCheckpoints = new() { "TestVM" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "VMs Without Checkpoints" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void HyperV_ExternalSwitch_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            VmsWithExternalSwitch = new() { "VM1" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("External Virtual Switch") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void HyperV_DefaultSwitchExternal_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            DefaultSwitchExternalAccess = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Default Switch") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void HyperV_GuestServices_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            VmsWithGuestServices = new() { "DevVM" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Guest Services") && f.Severity == Severity.Info);
    }

    // ── WSL ──

    [Fact]
    public void Wsl_NotInstalled_ProducesInfoOnly()
    {
        var state = new VirtualizationState { WslInstalled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        var wslFindings = result.Findings.Where(f => f.Category == "WSL").ToList();
        Assert.Single(wslFindings);
        Assert.Equal(Severity.Info, wslFindings[0].Severity);
    }

    [Fact]
    public void Wsl_Version1_ProducesWarning()
    {
        var state = new VirtualizationState { WslInstalled = true, WslDefaultVersion = 1 };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("WSL 1") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Wsl_Version2_ProducesPass()
    {
        var state = new VirtualizationState { WslInstalled = true, WslDefaultVersion = 2 };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("WSL 2") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Wsl_RootDistros_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslDistrosRunningAsRoot = new() { "Kali" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Running as Root") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Wsl_MirroredNetworking_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslNetworkingMirrored = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Mirrored") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Wsl_FirewallDisabled_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslFirewallEnabled = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Firewall Disabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Wsl_FirewallEnabled_ProducesPass()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslFirewallEnabled = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Firewall Enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Wsl_InteropAndPath_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslInteropEnabled = true,
            WslAppendWindowsPath = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Interop Fully Open") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Wsl_InteropOnly_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslInteropEnabled = true,
            WslAppendWindowsPath = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Interop Enabled") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Wsl_Systemd_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslSystemdEnabled = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("systemd") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Wsl_ManyDistros_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslDistributions = new() { "A", "B", "C", "D", "E", "F" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Many WSL") && f.Severity == Severity.Info);
    }

    // ── Sandbox ──

    [Fact]
    public void Sandbox_NotEnabled_ProducesInfo()
    {
        var state = new VirtualizationState { SandboxEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Sandbox Not Enabled") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Sandbox_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { SandboxEnabled = true, SandboxNetworkingEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "Windows Sandbox Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Sandbox_NetworkingEnabled_ProducesInfo()
    {
        var state = new VirtualizationState { SandboxEnabled = true, SandboxNetworkingEnabled = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Networking Enabled") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Sandbox_WritableFolders_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            SandboxEnabled = true,
            SandboxWritableMappedFolders = true,
            SandboxMappedFolders = new() { "C:\\Data" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Writable Mapped") && f.Severity == Severity.Warning);
    }

    // ── Docker ──

    [Fact]
    public void Docker_NotRunning_ProducesInfoOnly()
    {
        var state = new VirtualizationState { DockerRunning = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        var dockerFindings = result.Findings.Where(f => f.Category == "Docker").ToList();
        Assert.Single(dockerFindings);
        Assert.Equal(Severity.Info, dockerFindings[0].Severity);
    }

    [Fact]
    public void Docker_TcpExposedNoTls_ProducesCritical()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerTcpExposed = true,
            DockerTcpPort = 2375,
            DockerTlsVerify = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("TCP API Exposed Without TLS") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Docker_TcpExposedWithTls_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerTcpExposed = true,
            DockerTcpPort = 2376,
            DockerTlsVerify = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title == "Docker TCP API Exposed" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Docker_DefaultPrivileged_ProducesCritical()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerDefaultPrivileged = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Privileged") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Docker_RootContainers_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerRootContainers = new() { "app1" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Running as Root") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Docker_ContentTrustDisabled_ProducesWarning()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerContentTrustEnabled = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Content Trust") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Docker_NoUserNamespaces_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerUserNamespacesEnabled = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("User Namespaces") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Docker_IccEnabled_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerIccEnabled = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Inter-Container") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Docker_Experimental_ProducesInfo()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerExperimentalEnabled = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Experimental") && f.Severity == Severity.Info);
    }

    // ── VBS / Credential Guard ──

    [Fact]
    public void Vbs_NotRunning_ProducesWarning()
    {
        var state = new VirtualizationState { VbsRunning = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Virtualization-Based Security Not Running") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Vbs_Running_ProducesPass()
    {
        var state = new VirtualizationState { VbsRunning = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Virtualization-Based Security Active") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void CredentialGuard_Disabled_ProducesWarning()
    {
        var state = new VirtualizationState { CredentialGuardEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Credential Guard Not") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void CredentialGuard_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { CredentialGuardEnabled = true, CredentialGuardUefiLock = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Credential Guard Enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void CredentialGuard_NoUefiLock_ProducesInfo()
    {
        var state = new VirtualizationState { CredentialGuardEnabled = true, CredentialGuardUefiLock = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("UEFI Lock") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Hvci_Disabled_ProducesWarning()
    {
        var state = new VirtualizationState { HvciEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("HVCI Not") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Hvci_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { HvciEnabled = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("HVCI Enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void MemoryIntegrity_Disabled_ProducesWarning()
    {
        var state = new VirtualizationState { MemoryIntegrityEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Memory Integrity Disabled") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void MemoryIntegrity_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { MemoryIntegrityEnabled = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Memory Integrity Enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SecureBoot_Disabled_ProducesWarning()
    {
        var state = new VirtualizationState { SecureBootEnabled = false };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Secure Boot Not") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SecureBoot_Enabled_ProducesPass()
    {
        var state = new VirtualizationState { SecureBootEnabled = true };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Secure Boot Active") && f.Severity == Severity.Pass);
    }

    // ── Edge cases ──

    [Fact]
    public void EmptyState_ProducesFindings()
    {
        var state = new VirtualizationState();
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.True(result.Findings.Count > 0);
    }

    [Fact]
    public void EmptyState_NoCriticals()
    {
        var state = new VirtualizationState();
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.Equal(0, result.CriticalCount);
    }

    [Fact]
    public void AllFindingsHaveCategory()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.All(result.Findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Category)));
    }

    [Fact]
    public void AllFindingsHaveTitle()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.All(result.Findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Title)));
    }

    [Fact]
    public void AllFindingsHaveDescription()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.All(result.Findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Description)));
    }

    [Fact]
    public void WarningAndCriticalFindings_HaveRemediation()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        var actionable = result.Findings.Where(f => f.Severity is Severity.Warning or Severity.Critical);
        Assert.All(actionable, f => Assert.False(string.IsNullOrWhiteSpace(f.Remediation)));
    }

    [Fact]
    public void SecureState_CoversFiveCategories()
    {
        var result = MakeResult();
        AnalyzeState(MakeSecureState(), result);
        var categories = result.Findings.Select(f => f.Category).Distinct().ToList();
        Assert.Contains("Hyper-V", categories);
        Assert.Contains("WSL", categories);
        Assert.Contains("Sandbox", categories);
        Assert.Contains("Docker", categories);
        Assert.Contains("VBS", categories);
    }

    [Fact]
    public void InsecureState_CoversFiveCategories()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        var categories = result.Findings.Select(f => f.Category).Distinct().ToList();
        Assert.Equal(5, categories.Count);
    }

    [Fact]
    public void Docker_TcpNotExposed_NoCritical()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerTcpExposed = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        var dockerCriticals = result.Findings.Where(f => f.Category == "Docker" && f.Severity == Severity.Critical);
        Assert.Empty(dockerCriticals);
    }

    [Fact]
    public void Wsl_FewDistros_NoManyWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslDistributions = new() { "Ubuntu" }
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Many WSL"));
    }

    [Fact]
    public void Wsl_InteropDisabled_NoInteropWarning()
    {
        var state = new VirtualizationState
        {
            WslInstalled = true,
            WslDefaultVersion = 2,
            WslInteropEnabled = false,
            WslAppendWindowsPath = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Interop"));
    }

    [Fact]
    public void HyperV_NoExternalSwitch_NoWarning()
    {
        var state = new VirtualizationState
        {
            HyperVEnabled = true,
            VmsWithExternalSwitch = new()
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("External Virtual Switch"));
    }

    [Fact]
    public void Sandbox_NoWritableFolders_NoWarning()
    {
        var state = new VirtualizationState
        {
            SandboxEnabled = true,
            SandboxWritableMappedFolders = false,
            SandboxNetworkingEnabled = false
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Writable"));
    }

    [Fact]
    public void Docker_ContentTrustEnabled_NoWarning()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerContentTrustEnabled = true
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Content Trust Disabled"));
    }

    [Fact]
    public void Docker_NoRootContainers_NoWarning()
    {
        var state = new VirtualizationState
        {
            DockerRunning = true,
            DockerRootContainers = new()
        };
        var result = MakeResult();
        AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Running as Root") && f.Category == "Docker");
    }

    [Fact]
    public void OverallSeverity_InsecureState_IsCritical()
    {
        var result = MakeResult();
        AnalyzeState(MakeInsecureState(), result);
        Assert.Equal(Severity.Critical, result.OverallSeverity);
    }

    [Fact]
    public void OverallSeverity_SecureState_IsNotCritical()
    {
        var result = MakeResult();
        AnalyzeState(MakeSecureState(), result);
        Assert.NotEqual(Severity.Critical, result.OverallSeverity);
    }
}
