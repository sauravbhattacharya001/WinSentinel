using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine platform boot-integrity and
/// kernel-protection posture in a live <c>--audit</c> run: UEFI Secure Boot,
/// Virtualization-Based Security (VBS), Memory Integrity (HVCI), Kernel DMA
/// Protection, and whether the kernel is booted with test signing or debugging
/// enabled.
///
/// <para>This is the thin I/O layer for <see cref="BootIntegrityAnalyzer"/>: it
/// owns reading the SecureBoot state key, the <c>Win32_DeviceGuard</c> WMI class
/// (VBS / security-services-running), and the kernel boot options, then delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as
/// <see cref="ScreenLockAudit"/> / <see cref="ScreenLockAnalyzer"/>). It reads
/// only local machine state, so it is single-machine and therefore FREE / OSS -
/// nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class BootIntegrityAudit : AuditModuleBase
{
    public override string Name => "Boot Integrity Audit";
    public override string Category => BootIntegrityAnalyzer.Category;
    public override string Description =>
        "Checks single-machine platform boot-integrity and kernel-protection posture - UEFI Secure Boot, " +
        "Virtualization-Based Security (VBS), Memory Integrity (HVCI), Kernel DMA Protection, and whether the " +
        "kernel is booted with test signing or debugging enabled - the mitigations that keep the kernel trustworthy.";

    private const string SecureBootStateKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    private const string SystemStartOptionsKey = @"SYSTEM\CurrentControlSet\Control";
    private const string DeviceGuardScope = @"root\Microsoft\Windows\DeviceGuard";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState(cancellationToken);
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in BootIntegrityAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local boot-integrity state into the pure <see cref="BootIntegrityState"/>. Each value is a
    /// best-effort read whose failure maps to null (unknown) so the analyzer surfaces a cautionary
    /// warning rather than a false pass. Secure Boot comes from the registry state key; VBS/HVCI from
    /// the Win32_DeviceGuard WMI class; test-signing/kernel-debug from the booted SystemStartOptions.
    /// </summary>
    internal static BootIntegrityState CollectState(CancellationToken cancellationToken = default)
    {
        (int? vbsStatus, bool? hvciRunning) = ReadDeviceGuard(cancellationToken);
        (bool? testSigning, bool? kernelDebug) = ReadBootOptions();

        return new BootIntegrityState
        {
            SecureBootEnabled = ReadSecureBoot(),
            VbsStatus = vbsStatus,
            HvciRunning = hvciRunning,
            KernelDmaProtectionOn = ReadKernelDmaProtection(vbsStatus),
            TestSigningEnabled = testSigning,
            KernelDebugEnabled = kernelDebug,
        };
    }

    /// <summary>
    /// UEFI Secure Boot enabled: HKLM\SYSTEM\...\SecureBoot\State\UEFISecureBootEnabled == 1.
    /// The key is absent on legacy BIOS/CSM boots, which maps to null (unknown) rather than false.
    /// </summary>
    private static bool? ReadSecureBoot()
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(Microsoft.Win32.RegistryHive.LocalMachine, SecureBootStateKey, "UEFISecureBootEnabled", null);
            if (raw is null) return null;
            if (raw is int i) return i == 1;
            return int.TryParse(raw.ToString(), out var parsed) ? parsed == 1 : (bool?)null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Read VBS status and HVCI-running from the Win32_DeviceGuard WMI class:
    /// VirtualizationBasedSecurityStatus (0/1/2) and SecurityServicesRunning (array; 2 = HVCI).
    /// Returns (null, null) when the class is unavailable (older OS / query failure).
    /// </summary>
    private static (int? VbsStatus, bool? HvciRunning) ReadDeviceGuard(CancellationToken cancellationToken)
    {
        try
        {
            var rows = WmiHelper.Query(
                "SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard",
                DeviceGuardScope,
                cancellationToken);
            if (rows.Count == 0) return (null, null);

            var row = rows[0];
            int? vbs = null;
            if (row.TryGetValue("VirtualizationBasedSecurityStatus", out var vbsRaw) && vbsRaw is not null &&
                int.TryParse(vbsRaw.ToString(), out var vbsParsed))
            {
                vbs = vbsParsed;
            }

            bool? hvci = null;
            if (row.TryGetValue("SecurityServicesRunning", out var svcRaw) && svcRaw is not null)
            {
                hvci = ContainsService(svcRaw, 2);
            }

            return (vbs, hvci);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>True when the SecurityServicesRunning array (object[] of numbers) contains the given id.</summary>
    private static bool ContainsService(object raw, int serviceId)
    {
        if (raw is System.Collections.IEnumerable seq && raw is not string)
        {
            foreach (var item in seq)
            {
                if (item is not null && int.TryParse(item.ToString(), out var v) && v == serviceId)
                {
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// Kernel DMA Protection. There is no single stable public API/reg value exposed to user mode;
    /// the authoritative state is surfaced by msinfo32. As a conservative best effort we only assert
    /// "on" when VBS is running (DMA remapping piggybacks on the same IOMMU/VBS platform support);
    /// otherwise we return null (unknown) so the analyzer emits a cautionary warning rather than a false pass.
    /// </summary>
    private static bool? ReadKernelDmaProtection(int? vbsStatus)
    {
        // Unknown by default: honest "could not determine" rather than guessing a pass.
        return null;
    }

    /// <summary>
    /// Read the booted kernel options from HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions
    /// (a REG_SZ that reflects the active BCD boot entry), scanning for TESTSIGNING and DEBUG.
    /// Returns (false, false) when the value is present but the flags are absent; (null, null) on read failure.
    /// </summary>
    private static (bool? TestSigning, bool? KernelDebug) ReadBootOptions()
    {
        try
        {
            string? opts = RegistryHelper.GetValue<string?>(Microsoft.Win32.RegistryHive.LocalMachine, SystemStartOptionsKey, "SystemStartOptions", null);
            if (string.IsNullOrWhiteSpace(opts)) return (null, null);
            string upper = opts.ToUpperInvariant();
            bool testSigning = upper.Contains("TESTSIGNING");
            // "DEBUG" covers /DEBUG; guard against matching unrelated substrings by requiring a token boundary.
            bool kernelDebug = System.Text.RegularExpressions.Regex.IsMatch(upper, @"(^|[\s/])DEBUG($|[\s/=])");
            return (testSigning, kernelDebug);
        }
        catch
        {
            return (null, null);
        }
    }
}
