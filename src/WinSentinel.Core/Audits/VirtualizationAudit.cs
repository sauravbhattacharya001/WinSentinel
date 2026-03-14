using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits virtualization security configuration including:
/// - Hyper-V isolation and settings
/// - WSL version, distribution security, networking exposure
/// - Windows Sandbox availability and configuration
/// - Docker Desktop / container daemon security
/// - Credential Guard and VBS (Virtualization-Based Security)
/// - Hypervisor-enforced code integrity (HVCI)
/// </summary>
public class VirtualizationAudit : IAuditModule
{
    public string Name => "Virtualization Security Audit";
    public string Category => "Virtualization";
    public string Description =>
        "Checks Hyper-V, WSL, Windows Sandbox, Docker, and virtualization-based " +
        "security features for misconfigurations and exposure risks.";

    // ── State DTO ──────────────────────────────────────────────────────

    /// <summary>
    /// Data transfer object for virtualization environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class VirtualizationState
    {
        // ── Hyper-V ──
        /// <summary>Whether Hyper-V feature is enabled.</summary>
        public bool HyperVEnabled { get; set; }

        /// <summary>Whether Hyper-V management tools are installed.</summary>
        public bool HyperVManagementToolsInstalled { get; set; }

        /// <summary>Running VM names.</summary>
        public List<string> RunningVMs { get; set; } = new();

        /// <summary>VMs with no checkpoints (snapshots) configured.</summary>
        public List<string> VmsWithoutCheckpoints { get; set; } = new();

        /// <summary>VMs using enhanced session mode.</summary>
        public List<string> VmsWithEnhancedSession { get; set; } = new();

        /// <summary>VMs with external virtual switch (bridged networking).</summary>
        public List<string> VmsWithExternalSwitch { get; set; } = new();

        /// <summary>VMs with guest services integration enabled.</summary>
        public List<string> VmsWithGuestServices { get; set; } = new();

        /// <summary>Whether default virtual switch allows external access.</summary>
        public bool DefaultSwitchExternalAccess { get; set; }

        // ── WSL ──
        /// <summary>Whether WSL is installed.</summary>
        public bool WslInstalled { get; set; }

        /// <summary>WSL default version (1 or 2).</summary>
        public int WslDefaultVersion { get; set; }

        /// <summary>Installed WSL distribution names.</summary>
        public List<string> WslDistributions { get; set; } = new();

        /// <summary>Distributions running as root by default.</summary>
        public List<string> WslDistrosRunningAsRoot { get; set; } = new();

        /// <summary>Whether WSL networking is set to mirrored (shared host network).</summary>
        public bool WslNetworkingMirrored { get; set; }

        /// <summary>Whether WSL has autoMemoryReclaim enabled.</summary>
        public bool WslAutoMemoryReclaim { get; set; }

        /// <summary>Whether WSL firewall is enabled.</summary>
        public bool WslFirewallEnabled { get; set; }

        /// <summary>Whether WSL has DNS tunneling enabled (exposes host DNS).</summary>
        public bool WslDnsTunnelingEnabled { get; set; }

        /// <summary>Whether systemd is enabled in WSL (broader attack surface).</summary>
        public bool WslSystemdEnabled { get; set; }

        /// <summary>Whether Windows paths are appended to WSL PATH (interop risk).</summary>
        public bool WslAppendWindowsPath { get; set; } = true;

        /// <summary>Whether WSL interop (running Windows executables from Linux) is enabled.</summary>
        public bool WslInteropEnabled { get; set; } = true;

        // ── Windows Sandbox ──
        /// <summary>Whether Windows Sandbox feature is enabled.</summary>
        public bool SandboxEnabled { get; set; }

        /// <summary>Whether sandbox networking is enabled in config.</summary>
        public bool SandboxNetworkingEnabled { get; set; } = true;

        /// <summary>Whether sandbox has mapped folders with write access.</summary>
        public bool SandboxWritableMappedFolders { get; set; }

        /// <summary>Mapped folder paths in sandbox config.</summary>
        public List<string> SandboxMappedFolders { get; set; } = new();

        /// <summary>Whether sandbox vGPU is enabled.</summary>
        public bool SandboxVGpuEnabled { get; set; } = true;

        // ── Docker ──
        /// <summary>Whether Docker daemon is running.</summary>
        public bool DockerRunning { get; set; }

        /// <summary>Whether Docker is exposing TCP API without TLS.</summary>
        public bool DockerTcpExposed { get; set; }

        /// <summary>Docker TCP port (0 if not exposed).</summary>
        public int DockerTcpPort { get; set; }

        /// <summary>Whether Docker daemon has TLS verification enabled.</summary>
        public bool DockerTlsVerify { get; set; }

        /// <summary>Whether Docker uses experimental features.</summary>
        public bool DockerExperimentalEnabled { get; set; }

        /// <summary>Whether Docker default network allows inter-container communication.</summary>
        public bool DockerIccEnabled { get; set; } = true;

        /// <summary>Whether Docker runs containers in privileged mode by default.</summary>
        public bool DockerDefaultPrivileged { get; set; }

        /// <summary>Number of running containers.</summary>
        public int DockerRunningContainers { get; set; }

        /// <summary>Containers running as root.</summary>
        public List<string> DockerRootContainers { get; set; } = new();

        /// <summary>Whether Docker content trust (image signing) is enabled.</summary>
        public bool DockerContentTrustEnabled { get; set; }

        /// <summary>Whether Docker uses user namespaces for isolation.</summary>
        public bool DockerUserNamespacesEnabled { get; set; }

        // ── VBS / Credential Guard ──
        /// <summary>Whether Virtualization-Based Security is running.</summary>
        public bool VbsRunning { get; set; }

        /// <summary>Whether Credential Guard is enabled.</summary>
        public bool CredentialGuardEnabled { get; set; }

        /// <summary>Whether HVCI (Hypervisor-enforced Code Integrity) is enabled.</summary>
        public bool HvciEnabled { get; set; }

        /// <summary>Whether Secure Boot is active.</summary>
        public bool SecureBootEnabled { get; set; }

        /// <summary>Whether UEFI lock is set for Credential Guard.</summary>
        public bool CredentialGuardUefiLock { get; set; }

        /// <summary>Whether memory integrity (core isolation) is enabled.</summary>
        public bool MemoryIntegrityEnabled { get; set; }
    }

    // ── Analysis ───────────────────────────────────────────────────────

    /// <summary>Analyze virtualization state and produce findings (testable, no OS calls).</summary>
    public static void AnalyzeState(VirtualizationState state, AuditResult result)
    {
        CheckHyperV(state, result);
        CheckWsl(state, result);
        CheckSandbox(state, result);
        CheckDocker(state, result);
        CheckVbs(state, result);
    }

    // ── Hyper-V ──

    private static void CheckHyperV(VirtualizationState state, AuditResult result)
    {
        const string cat = "Hyper-V";

        if (!state.HyperVEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Hyper-V Not Enabled",
                "Hyper-V is not enabled on this system. No VM isolation checks needed.",
                cat));
            return;
        }

        result.Findings.Add(Finding.Pass(
            "Hyper-V Enabled",
            "Hyper-V is enabled, providing hardware-level VM isolation.",
            cat));

        if (state.RunningVMs.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Running Virtual Machines",
                $"{state.RunningVMs.Count} VM(s) running: {string.Join(", ", state.RunningVMs)}.",
                cat));
        }

        if (state.VmsWithoutCheckpoints.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "VMs Without Checkpoints",
                $"{state.VmsWithoutCheckpoints.Count} VM(s) have no checkpoints for recovery: " +
                $"{string.Join(", ", state.VmsWithoutCheckpoints)}.",
                cat,
                "Create checkpoints for VMs to enable quick recovery from misconfigurations or compromise."));
        }

        if (state.VmsWithExternalSwitch.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "VMs on External Virtual Switch",
                $"{state.VmsWithExternalSwitch.Count} VM(s) use external switch (bridged networking), " +
                $"exposing them directly to the physical network: {string.Join(", ", state.VmsWithExternalSwitch)}.",
                cat,
                "Use internal or private switches unless VMs require direct network access. " +
                "External switches bypass host firewall for VM traffic."));
        }

        if (state.DefaultSwitchExternalAccess)
        {
            result.Findings.Add(Finding.Warning(
                "Default Switch Allows External Access",
                "The default Hyper-V virtual switch is configured to allow external network access.",
                cat,
                "Review whether VMs need direct external network connectivity."));
        }

        if (state.VmsWithGuestServices.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "VMs with Guest Services Integration",
                $"{state.VmsWithGuestServices.Count} VM(s) have guest services enabled " +
                $"(file copy between host/guest): {string.Join(", ", state.VmsWithGuestServices)}.",
                cat,
                "Guest services allow file transfer between host and guest. Disable if not needed."));
        }
    }

    // ── WSL ──

    private static void CheckWsl(VirtualizationState state, AuditResult result)
    {
        const string cat = "WSL";

        if (!state.WslInstalled)
        {
            result.Findings.Add(Finding.Info(
                "WSL Not Installed",
                "Windows Subsystem for Linux is not installed.",
                cat));
            return;
        }

        if (state.WslDefaultVersion == 1)
        {
            result.Findings.Add(Finding.Warning(
                "WSL 1 Default Version",
                "WSL default version is 1, which runs Linux in a translation layer without " +
                "full VM isolation. WSL 2 uses a real Linux kernel in a lightweight VM.",
                cat,
                "Set WSL default version to 2: wsl --set-default-version 2",
                "wsl --set-default-version 2"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "WSL 2 Default Version",
                "WSL default version is 2, providing better isolation via lightweight VM.",
                cat));
        }

        if (state.WslDistrosRunningAsRoot.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "WSL Distributions Running as Root",
                $"{state.WslDistrosRunningAsRoot.Count} distribution(s) default to root user: " +
                $"{string.Join(", ", state.WslDistrosRunningAsRoot)}. Running as root increases " +
                "the impact of any compromise within the WSL environment.",
                cat,
                "Create a non-root user and set as default: " +
                "wsl -d <distro> -u root useradd -m <user> && " +
                "wsl -d <distro> --default-user <user>"));
        }

        if (state.WslNetworkingMirrored)
        {
            result.Findings.Add(Finding.Warning(
                "WSL Mirrored Networking",
                "WSL networking is set to mirrored mode, sharing the host network stack. " +
                "Services running in WSL are directly accessible from the network.",
                cat,
                "Use NAT networking (default) to isolate WSL network traffic from the host."));
        }

        if (!state.WslFirewallEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "WSL Firewall Disabled",
                "The WSL firewall is not enabled. WSL traffic is not filtered by Windows Firewall rules.",
                cat,
                "Enable WSL firewall in .wslconfig: [wsl2] firewall=true"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "WSL Firewall Enabled",
                "WSL firewall is enabled, filtering traffic with Windows Firewall rules.",
                cat));
        }

        if (state.WslInteropEnabled && state.WslAppendWindowsPath)
        {
            result.Findings.Add(Finding.Warning(
                "WSL Windows Interop Fully Open",
                "WSL can execute Windows binaries and has Windows PATH appended. " +
                "A compromised WSL environment can directly execute host Windows programs.",
                cat,
                "Restrict interop in /etc/wsl.conf: [interop] enabled=false appendWindowsPath=false"));
        }
        else if (state.WslInteropEnabled)
        {
            result.Findings.Add(Finding.Info(
                "WSL Windows Interop Enabled",
                "WSL can execute Windows binaries. Consider disabling if not needed.",
                cat));
        }

        if (state.WslSystemdEnabled)
        {
            result.Findings.Add(Finding.Info(
                "WSL systemd Enabled",
                "systemd is enabled in WSL, providing full service management but increasing attack surface.",
                cat,
                "Disable systemd if not needed: [boot] systemd=false in /etc/wsl.conf"));
        }

        if (state.WslDistributions.Count > 5)
        {
            result.Findings.Add(Finding.Info(
                "Many WSL Distributions Installed",
                $"{state.WslDistributions.Count} WSL distributions are installed. " +
                "Each distribution is an additional attack surface.",
                cat,
                "Remove unused distributions: wsl --unregister <distro>"));
        }
    }

    // ── Windows Sandbox ──

    private static void CheckSandbox(VirtualizationState state, AuditResult result)
    {
        const string cat = "Sandbox";

        if (!state.SandboxEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Windows Sandbox Not Enabled",
                "Windows Sandbox is not enabled. Consider enabling for safe testing of untrusted software.",
                cat,
                "Enable via: Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online",
                "Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online"));
            return;
        }

        result.Findings.Add(Finding.Pass(
            "Windows Sandbox Enabled",
            "Windows Sandbox is available for isolated testing of untrusted applications.",
            cat));

        if (state.SandboxNetworkingEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Sandbox Networking Enabled",
                "Windows Sandbox has networking enabled. Untrusted apps can access the network.",
                cat,
                "Disable networking in .wsb config: <Networking>Disable</Networking>"));
        }

        if (state.SandboxWritableMappedFolders)
        {
            result.Findings.Add(Finding.Warning(
                "Sandbox Has Writable Mapped Folders",
                $"Windows Sandbox has mapped folders with write access: " +
                $"{string.Join(", ", state.SandboxMappedFolders)}. " +
                "Untrusted code in the sandbox can modify host files.",
                cat,
                "Set mapped folders to read-only: <ReadOnly>true</ReadOnly> in .wsb config."));
        }
    }

    // ── Docker ──

    private static void CheckDocker(VirtualizationState state, AuditResult result)
    {
        const string cat = "Docker";

        if (!state.DockerRunning)
        {
            result.Findings.Add(Finding.Info(
                "Docker Not Running",
                "Docker daemon is not running on this system.",
                cat));
            return;
        }

        result.Findings.Add(Finding.Info(
            "Docker Running",
            $"Docker daemon is running with {state.DockerRunningContainers} container(s) active.",
            cat));

        if (state.DockerTcpExposed && !state.DockerTlsVerify)
        {
            result.Findings.Add(Finding.Critical(
                "Docker TCP API Exposed Without TLS",
                $"Docker daemon TCP API is exposed on port {state.DockerTcpPort} without TLS verification. " +
                "Anyone with network access can control the Docker daemon and gain root-equivalent access.",
                cat,
                "Enable TLS verification or disable TCP listener. Use Unix socket for local access.",
                "Set DOCKER_TLS_VERIFY=1 and configure TLS certificates."));
        }
        else if (state.DockerTcpExposed)
        {
            result.Findings.Add(Finding.Warning(
                "Docker TCP API Exposed",
                $"Docker daemon TCP API is exposed on port {state.DockerTcpPort}. " +
                "TLS is enabled, but TCP exposure increases attack surface.",
                cat,
                "Prefer Unix socket for local access. Restrict TCP to trusted networks."));
        }

        if (state.DockerDefaultPrivileged)
        {
            result.Findings.Add(Finding.Critical(
                "Docker Default Privileged Mode",
                "Docker is configured to run containers in privileged mode by default. " +
                "Privileged containers have full access to host devices and kernel capabilities.",
                cat,
                "Remove --privileged default. Use specific --cap-add flags for needed capabilities."));
        }

        if (state.DockerRootContainers.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Containers Running as Root",
                $"{state.DockerRootContainers.Count} container(s) running as root: " +
                $"{string.Join(", ", state.DockerRootContainers)}.",
                cat,
                "Use USER directive in Dockerfiles or --user flag to run as non-root."));
        }

        if (!state.DockerContentTrustEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Docker Content Trust Disabled",
                "Docker Content Trust (image signing) is not enabled. " +
                "Unsigned/tampered images can be pulled and executed.",
                cat,
                "Enable content trust: set DOCKER_CONTENT_TRUST=1",
                "setx DOCKER_CONTENT_TRUST 1"));
        }

        if (!state.DockerUserNamespacesEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Docker User Namespaces Not Enabled",
                "Docker is not using user namespace remapping. Container root maps to host root.",
                cat,
                "Enable userns-remap in Docker daemon.json for better isolation."));
        }

        if (state.DockerIccEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Docker Inter-Container Communication Enabled",
                "Default Docker bridge network allows inter-container communication (ICC). " +
                "Containers can communicate freely on the default bridge.",
                cat,
                "Set \"icc\": false in daemon.json and use user-defined networks for needed connectivity."));
        }

        if (state.DockerExperimentalEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Docker Experimental Features Enabled",
                "Docker experimental features are enabled. These features may have security implications.",
                cat,
                "Disable experimental features in production: set \"experimental\": false in daemon.json."));
        }
    }

    // ── VBS / Credential Guard ──

    private static void CheckVbs(VirtualizationState state, AuditResult result)
    {
        const string cat = "VBS";

        if (!state.VbsRunning)
        {
            result.Findings.Add(Finding.Warning(
                "Virtualization-Based Security Not Running",
                "VBS is not active. Credential Guard, HVCI, and other VBS features are unavailable. " +
                "VBS provides hardware-level isolation for sensitive Windows security operations.",
                cat,
                "Enable VBS via Group Policy or registry. Requires UEFI Secure Boot and compatible hardware."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Virtualization-Based Security Active",
                "VBS is running, providing hardware-level isolation for security features.",
                cat));
        }

        if (!state.CredentialGuardEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Credential Guard Not Enabled",
                "Windows Credential Guard is not active. NTLM hashes and Kerberos tickets " +
                "are stored in standard process memory, vulnerable to credential theft tools " +
                "like Mimikatz.",
                cat,
                "Enable Credential Guard via Group Policy: " +
                "Computer Configuration > Administrative Templates > System > Device Guard > " +
                "Turn On Virtualization Based Security > Credential Guard Configuration.",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags /t REG_DWORD /d 1 /f"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Credential Guard Enabled",
                "Credential Guard is protecting NTLM hashes and Kerberos tickets in isolated memory.",
                cat));

            if (!state.CredentialGuardUefiLock)
            {
                result.Findings.Add(Finding.Info(
                    "Credential Guard UEFI Lock Not Set",
                    "Credential Guard is enabled but without UEFI lock. It can be disabled remotely via policy change.",
                    cat,
                    "Set UEFI lock to prevent remote disabling of Credential Guard."));
            }
        }

        if (!state.HvciEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "HVCI Not Enabled",
                "Hypervisor-enforced Code Integrity (HVCI) is not active. " +
                "Kernel-mode code integrity checks run without hypervisor protection, " +
                "allowing potential kernel driver exploits.",
                cat,
                "Enable HVCI (Memory Integrity) in Windows Security > Device Security > Core Isolation.",
                "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 1 /f"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "HVCI Enabled",
                "Hypervisor-enforced Code Integrity is active, protecting kernel code from tampering.",
                cat));
        }

        if (!state.MemoryIntegrityEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Memory Integrity Disabled",
                "Core isolation memory integrity is disabled. This leaves the kernel vulnerable " +
                "to code injection attacks from malicious drivers.",
                cat,
                "Enable Memory Integrity in Windows Security > Device Security > Core Isolation Details."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Memory Integrity Enabled",
                "Core isolation memory integrity is active.",
                cat));
        }

        if (!state.SecureBootEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Secure Boot Not Active",
                "Secure Boot is not enabled. The boot process is not protected against " +
                "bootkits and rootkits. VBS and Credential Guard require Secure Boot.",
                cat,
                "Enable Secure Boot in UEFI/BIOS settings."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Secure Boot Active",
                "Secure Boot is protecting the boot process against unauthorized firmware and bootloaders.",
                cat));
        }
    }

    // ── Live Audit ─────────────────────────────────────────────────────

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            var state = await CollectStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>Collect live virtualization state from the OS.</summary>
    internal static async Task<VirtualizationState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new VirtualizationState();
        await Task.CompletedTask; // Placeholder — real collection uses WMI/PowerShell/registry

        try
        {
            state.HyperVEnabled = RegistryHelper.GetValue<int>(
                Microsoft.Win32.RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "Enabled") == 1;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            state.WslInstalled = File.Exists(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            var vbsStatus = RegistryHelper.GetValue<int>(
                Microsoft.Win32.RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity");
            state.VbsRunning = vbsStatus == 1;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            var lsaCfg = RegistryHelper.GetValue<int>(
                Microsoft.Win32.RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags");
            state.CredentialGuardEnabled = lsaCfg is 1 or 2;
            state.CredentialGuardUefiLock = lsaCfg == 2;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            var hvci = RegistryHelper.GetValue<int>(
                Microsoft.Win32.RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                "Enabled");
            state.HvciEnabled = hvci == 1;
            state.MemoryIntegrityEnabled = hvci == 1;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            state.SecureBootEnabled = RegistryHelper.GetValue<int>(
                Microsoft.Win32.RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 1;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            state.DockerRunning = System.Diagnostics.Process.GetProcessesByName("dockerd").Length > 0 ||
                                  System.Diagnostics.Process.GetProcessesByName("com.docker.service").Length > 0;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return state;
    }
}
