using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits USB and removable media security posture: connected device history,
/// autorun/autoplay status, BitLocker-to-Go coverage, and USB write-protect policy.
///
/// This module only <em>collects</em> raw state from the registry and BitLocker
/// cmdlets; every decision (which value is a Pass/Warning/Info) lives in the pure,
/// unit-tested <see cref="UsbAnalyzer"/>.
/// </summary>
public class UsbAudit : AuditModuleBase
{
    public override string Name => "USB & Removable Media Audit";
    public override string Category => "USB";
    public override string Description =>
        "Checks USB device history, autorun/autoplay settings, BitLocker-to-Go coverage, " +
        "and USB write-protect policies for removable storage.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = new UsbAnalyzer.UsbState
        {
            NoDriveTypeAutoRun = CollectNoDriveTypeAutoRun(),
            AutoPlayDisabled = CollectAutoPlayDisabled(),
            UsbWriteProtected = CollectUsbWriteProtected(),
            DenyRemovableDevices = CollectDenyRemovableDevices(),
            UsbStorStartValue = CollectUsbStorStart(),
            RdvDenyWriteAccess = CollectRdvDenyWriteAccess(),
            RequireRemovableEncryption = CollectRequireRemovableEncryption(),
        };

        CollectUsbDeviceHistory(state);
        state.BitLockerDataVolumeStatusAvailable =
            await CollectBitLockerDataVolumeStatusAsync(cancellationToken);

        result.Findings.AddRange(UsbAnalyzer.Analyze(state));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Raw collection (real Windows API access only - no decision logic)
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads <c>NoDriveTypeAutoRun</c>, preferring the HKLM machine policy and
    /// falling back to the HKCU user policy. Returns <c>null</c> when neither is set.
    /// </summary>
    private static int? CollectNoDriveTypeAutoRun()
    {
        const string policyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        const string valueName = "NoDriveTypeAutoRun";

        using (var key = Registry.LocalMachine.OpenSubKey(policyPath))
        {
            if (key?.GetValue(valueName) is int val)
                return val;
        }

        using (var key = Registry.CurrentUser.OpenSubKey(policyPath))
        {
            if (key?.GetValue(valueName) is int val)
                return val;
        }

        return null;
    }

    /// <summary>
    /// AutoPlay is considered disabled when either the HKCU <c>DisableAutoplay=1</c>
    /// or the HKLM Group Policy <c>NoAutoplayfornonVolume=1</c> is set.
    /// </summary>
    private static bool CollectAutoPlayDisabled()
    {
        const string autoPlayPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers";
        using (var key = Registry.CurrentUser.OpenSubKey(autoPlayPath))
        {
            if (key?.GetValue("DisableAutoplay") is int val && val == 1)
                return true;
        }

        const string gpPath = @"SOFTWARE\Policies\Microsoft\Windows\Explorer";
        using (var key = Registry.LocalMachine.OpenSubKey(gpPath))
        {
            if (key?.GetValue("NoAutoplayfornonVolume") is int val && val == 1)
                return true;
        }

        return false;
    }

    private static bool CollectUsbWriteProtected()
    {
        const string storagePath = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
        using var key = Registry.LocalMachine.OpenSubKey(storagePath);
        return key?.GetValue("WriteProtect") is int val && val == 1;
    }

    private static bool CollectDenyRemovableDevices()
    {
        const string denyPath = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        using var key = Registry.LocalMachine.OpenSubKey(denyPath);
        return key?.GetValue("DenyRemovableDevices") is int val && val == 1;
    }

    private static int? CollectUsbStorStart()
    {
        const string usbStorPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
        using var key = Registry.LocalMachine.OpenSubKey(usbStorPath);
        if (key?.GetValue("Start") is int val)
            return val;
        return null;
    }

    private static bool CollectRdvDenyWriteAccess()
    {
        const string blPath = @"SOFTWARE\Policies\Microsoft\FVE";
        using var key = Registry.LocalMachine.OpenSubKey(blPath);
        return key?.GetValue("RDVDenyWriteAccess") is int val && val == 1;
    }

    private static bool CollectRequireRemovableEncryption()
    {
        const string fvePath = @"SOFTWARE\Policies\Microsoft\FVE";
        using var key = Registry.LocalMachine.OpenSubKey(fvePath);
        // RDVConfigureBDE = 1 means BitLocker is required for removable drives
        return key?.GetValue("RDVConfigureBDE") is int val && val == 1;
    }

    /// <summary>
    /// Enumerates USB device connection history from <c>USBSTOR</c>, populating the
    /// device count and up to <see cref="UsbAnalyzer.MaxRecentDevicesListed"/>
    /// friendly names.
    /// </summary>
    private static void CollectUsbDeviceHistory(UsbAnalyzer.UsbState state)
    {
        const string usbStorPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";

        try
        {
            using var usbKey = Registry.LocalMachine.OpenSubKey(usbStorPath);
            if (usbKey == null) return;

            foreach (var deviceClass in usbKey.GetSubKeyNames())
            {
                using var classKey = usbKey.OpenSubKey(deviceClass);
                if (classKey == null) continue;

                foreach (var instance in classKey.GetSubKeyNames())
                {
                    state.UsbDeviceCount++;
                    using var instanceKey = classKey.OpenSubKey(instance);
                    var friendlyName = instanceKey?.GetValue("FriendlyName") as string;
                    if (!string.IsNullOrWhiteSpace(friendlyName) &&
                        state.RecentDeviceNames.Count < UsbAnalyzer.MaxRecentDevicesListed)
                    {
                        state.RecentDeviceNames.Add(friendlyName);
                    }
                }
            }
        }
        catch
        {
            // Access denied or key missing — not critical
        }
    }

    /// <summary>
    /// Queries <c>Get-BitLockerVolume</c> for data volumes; returns true when a
    /// non-null payload was retrieved (BitLocker cmdlets may be unavailable on some
    /// editions, in which case false is returned).
    /// </summary>
    private static async Task<bool> CollectBitLockerDataVolumeStatusAsync(CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' } | " +
                "Select-Object -Property MountPoint, ProtectionStatus, VolumeStatus | ConvertTo-Json -Compress",
                ct);

            return !string.IsNullOrWhiteSpace(output) && output.Trim() != "null";
        }
        catch
        {
            // BitLocker cmdlets may not be available on all editions
            return false;
        }
    }
}
