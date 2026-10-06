using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for platform boot-integrity and kernel-protection
/// hardening on a single machine. These are the low-level mitigations that
/// decide whether the kernel itself can be trusted before any audit module even
/// runs - if Secure Boot is off or test-signed/debug kernels are allowed, every
/// other finding sits on sand:
///
///   * SecureBoot         - UEFI Secure Boot verifies the bootloader/kernel
///                          signature chain, blocking bootkits. Off = unsigned
///                          boot components can load.
///   * VBS (Virtualization-Based Security) - runs sensitive kernel components in
///                          a VTL1 enclave isolated from the normal kernel. The
///                          foundation for HVCI and Credential Guard.
///   * HVCI (Memory Integrity / Hypervisor-enforced Code Integrity) - validates
///                          every kernel-mode driver/binary signature in the VBS
///                          enclave, blocking unsigned/tampered kernel code.
///   * Kernel DMA Protection - blocks malicious peripherals (Thunderbolt/PCIe)
///                          from DMA-reading memory before the OS is in control
///                          (the classic "evil maid" / drive-by DMA attack).
///   * TestSigning        - bcdedit TESTSIGNING ON lets unsigned (test-signed)
///                          kernel drivers load, defeating driver signature
///                          enforcement. Must be off on production machines.
///   * KernelDebug        - a kernel debugger attached at boot (bcdedit /debug on)
///                          lets anyone with the transport inspect/modify kernel
///                          memory. Must be off on production machines.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// firmware/registry/boot-config state only. Nothing multi-machine, nothing
/// license-gated. All rules operate on a synthetic <see cref="BootIntegrityState"/>
/// so they can be unit tested directly, mirroring the established
/// <see cref="ScreenLockAnalyzer"/> analyzer pattern (collector owns I/O, the
/// analyzer owns decisions).
/// </summary>
public static class BootIntegrityAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Boot Integrity";

    /// <summary>
    /// Evaluate the collected boot-integrity state and return one finding per
    /// check (a Pass when the setting is already safe, otherwise a Warning or
    /// Critical). Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeSecureBoot(state),
            AnalyzeVbs(state),
            AnalyzeHvci(state),
            AnalyzeKernelDmaProtection(state),
            AnalyzeTestSigning(state),
            AnalyzeKernelDebug(state),
        };
    }

    /// <summary>UEFI Secure Boot must be enabled to verify the boot signature chain.</summary>
    public static Finding AnalyzeSecureBoot(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.SecureBootEnabled == true)
        {
            return Finding.Pass(
                "UEFI Secure Boot is enabled",
                "Secure Boot is on, so the firmware verifies the signature of the bootloader " +
                "and kernel before executing them, blocking bootkits and unsigned boot code.",
                Category);
        }

        if (state.SecureBootEnabled == false)
        {
            return Finding.Warning(
                "UEFI Secure Boot is disabled",
                "Secure Boot is off, so the firmware does not verify the boot chain. Unsigned " +
                "or tampered bootloaders/kernels can load, enabling bootkit persistence below the OS.",
                Category,
                remediation: "Enable Secure Boot in UEFI firmware settings. Requires a UEFI (non-legacy/CSM) boot and a GPT system disk.");
        }

        return Finding.Warning(
            "Secure Boot state could not be determined",
            "The Secure Boot state is unknown (often a legacy BIOS/CSM boot, where Secure Boot " +
            "cannot apply). Confirm the system boots in UEFI mode with Secure Boot enabled.",
            Category,
            remediation: "Verify the machine boots in UEFI mode (not legacy/CSM) and enable Secure Boot in firmware.");
    }

    /// <summary>Virtualization-Based Security should be running (foundation for HVCI/Credential Guard).</summary>
    public static Finding AnalyzeVbs(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // VbsStatus: 0 = not enabled, 1 = enabled but not running, 2 = enabled and running.
        if (state.VbsStatus == 2)
        {
            return Finding.Pass(
                "Virtualization-Based Security is running",
                "VBS is enabled and running, isolating sensitive kernel components (code " +
                "integrity, credentials) in a hypervisor-protected VTL1 enclave.",
                Category);
        }

        if (state.VbsStatus == 1)
        {
            return Finding.Warning(
                "Virtualization-Based Security is configured but not running",
                "VBS is enabled in policy but not currently running. The isolation that HVCI " +
                "and Credential Guard depend on is not active, so those protections are inert.",
                Category,
                remediation: "Ensure the hypervisor platform and required virtualization firmware settings (VT-x/AMD-V, IOMMU) are on, then reboot so VBS starts.");
        }

        return Finding.Warning(
            "Virtualization-Based Security is not enabled",
            "VBS is not enabled, so there is no hypervisor-isolated enclave to protect kernel " +
            "code integrity or credentials. HVCI and Credential Guard cannot run without it.",
            Category,
            remediation: "Enable VBS via Group Policy (Device Guard) or Windows Security > Device Security, ensuring virtualization firmware (VT-x/AMD-V + IOMMU) is enabled, then reboot.");
    }

    /// <summary>HVCI (Memory Integrity) must be running to enforce kernel-mode code signatures.</summary>
    public static Finding AnalyzeHvci(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.HvciRunning == true)
        {
            return Finding.Pass(
                "Memory Integrity (HVCI) is running",
                "Hypervisor-enforced Code Integrity is active, validating every kernel-mode " +
                "driver and binary signature in the VBS enclave and blocking unsigned or " +
                "tampered kernel code.",
                Category);
        }

        return Finding.Warning(
            "Memory Integrity (HVCI) is not running",
            "Hypervisor-enforced Code Integrity is off, so kernel-mode driver signatures are " +
            "not validated by the isolated enclave. A vulnerable or malicious driver can run " +
            "with full kernel privileges.",
            Category,
            remediation: "Enable Windows Security > Device Security > Core Isolation > Memory Integrity (requires VBS and signed drivers), then reboot.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name Enabled -Type DWord -Value 1");
    }

    /// <summary>Kernel DMA Protection should be on to block pre-boot DMA peripheral attacks.</summary>
    public static Finding AnalyzeKernelDmaProtection(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.KernelDmaProtectionOn == true)
        {
            return Finding.Pass(
                "Kernel DMA Protection is enabled",
                "Kernel DMA Protection is on, blocking malicious Thunderbolt/PCIe peripherals " +
                "from reading system memory via DMA before the OS controls the device.",
                Category);
        }

        if (state.KernelDmaProtectionOn == false)
        {
            return Finding.Warning(
                "Kernel DMA Protection is not enabled",
                "Kernel DMA Protection is off, so a malicious plug-in peripheral (Thunderbolt/" +
                "PCIe) can DMA-read memory - including secrets - in the classic drive-by/evil-maid attack.",
                Category,
                remediation: "Kernel DMA Protection requires UEFI/IOMMU firmware support and VBS; enable VBS and ensure the firmware exposes DMA remapping, then reboot.");
        }

        return Finding.Warning(
            "Kernel DMA Protection state could not be determined",
            "Kernel DMA Protection status is unknown (the platform may lack the required IOMMU/" +
            "firmware support). Confirm DMA protection is active on portable/Thunderbolt-equipped machines.",
            Category,
            remediation: "Verify firmware IOMMU/DMA-remapping support and that VBS is enabled; check msinfo32 for 'Kernel DMA Protection'.");
    }

    /// <summary>Test signing must be OFF so unsigned kernel drivers cannot load.</summary>
    public static Finding AnalyzeTestSigning(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.TestSigningEnabled == true)
        {
            return Finding.Critical(
                "Kernel test signing is enabled",
                "Boot configuration has TESTSIGNING ON, which lets unsigned (test-signed) " +
                "kernel-mode drivers load. Driver Signature Enforcement is effectively defeated, " +
                "so a malicious or vulnerable unsigned driver can run in the kernel.",
                Category,
                remediation: "Disable test signing: run 'bcdedit /set testsigning off' from an elevated prompt and reboot.",
                fixCommand: "bcdedit /set testsigning off");
        }

        return Finding.Pass(
            "Kernel test signing is disabled",
            "TESTSIGNING is off, so Driver Signature Enforcement is intact and only properly " +
            "signed kernel-mode drivers can load.",
            Category);
    }

    /// <summary>Kernel debugging must be OFF on production machines.</summary>
    public static Finding AnalyzeKernelDebug(BootIntegrityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.KernelDebugEnabled == true)
        {
            return Finding.Critical(
                "Kernel debugging is enabled at boot",
                "Boot configuration has kernel debugging ON (bcdedit /debug on). A debugger " +
                "attached over the configured transport can read and modify arbitrary kernel " +
                "memory, bypassing every OS protection. This does not belong on a production machine.",
                Category,
                remediation: "Disable kernel debugging: run 'bcdedit /debug off' from an elevated prompt and reboot.",
                fixCommand: "bcdedit /debug off");
        }

        return Finding.Pass(
            "Kernel debugging is disabled",
            "Boot debugging is off, so no kernel debugger can attach at boot to inspect or " +
            "tamper with kernel memory.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied platform boot-integrity / kernel-protection state.
/// Populated by the audit module's I/O layer (firmware queries, the
/// DeviceGuard WMI class, bcdedit / boot-config reads) and handed to
/// <see cref="BootIntegrityAnalyzer"/> for a pure decision. Nullable fields mean
/// "value absent / not readable"; the analyzer treats an unknown Secure Boot /
/// DMA state as a cautionary Warning rather than a silent Pass.
/// </summary>
public sealed record BootIntegrityState
{
    /// <summary>UEFI Secure Boot enabled. Null = could not be determined (e.g. legacy BIOS/CSM boot).</summary>
    public bool? SecureBootEnabled { get; init; }

    /// <summary>
    /// Win32_DeviceGuard.VirtualizationBasedSecurityStatus:
    /// 0 = not enabled, 1 = enabled but not running, 2 = enabled and running. Null = unknown.
    /// </summary>
    public int? VbsStatus { get; init; }

    /// <summary>HVCI / Memory Integrity running (DeviceGuard SecurityServicesRunning contains 2). Null = unknown.</summary>
    public bool? HvciRunning { get; init; }

    /// <summary>Kernel DMA Protection active. Null = platform/firmware support could not be determined.</summary>
    public bool? KernelDmaProtectionOn { get; init; }

    /// <summary>Boot config TESTSIGNING is ON (unsigned kernel drivers allowed). Null/false = off.</summary>
    public bool? TestSigningEnabled { get; init; }

    /// <summary>Boot config kernel debugging is ON. Null/false = off.</summary>
    public bool? KernelDebugEnabled { get; init; }
}
