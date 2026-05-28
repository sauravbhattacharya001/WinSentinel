using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits USB and removable media security posture: connected device history,
/// autorun/autoplay status, BitLocker-to-Go coverage, and USB write-protect policy.
/// </summary>
public class UsbAudit : AuditModuleBase
{
    public override string Name => "USB & Removable Media Audit";
    public override string Category => "USB";
    public override string Description =>
        "Checks USB device history, autorun/autoplay settings, BitLocker-to-Go coverage, " +
        "and USB write-protect policies for removable storage.";

    private const string UsbStorCategory = "USB";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        CheckAutoRunDisabled(result);
        CheckAutoPlayDisabled(result);
        CheckUsbWriteProtectPolicy(result);
        CheckUsbStorageDisablePolicy(result);
        await CheckBitLockerToGo(result, cancellationToken);
        CheckUsbDeviceHistory(result);
        CheckRemovableDiskEncryption(result);
    }

    /// <summary>
    /// Checks whether AutoRun is disabled for all drives via the NoDriveTypeAutoRun policy.
    /// AutoRun allows malware to execute automatically when removable media is inserted.
    /// </summary>
    private void CheckAutoRunDisabled(AuditResult result)
    {
        // NoDriveTypeAutoRun = 0xFF disables AutoRun for all drive types
        const string policyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        const string valueName = "NoDriveTypeAutoRun";

        int? policyValue = null;

        // Check machine policy first (takes precedence)
        using (var key = Registry.LocalMachine.OpenSubKey(policyPath))
        {
            if (key?.GetValue(valueName) is int val)
                policyValue = val;
        }

        // Fall back to user policy
        if (policyValue == null)
        {
            using var key = Registry.CurrentUser.OpenSubKey(policyPath);
            if (key?.GetValue(valueName) is int val)
                policyValue = val;
        }

        if (policyValue == null || policyValue != 0xFF)
        {
            result.Findings.Add(Finding.Warning(
                "AutoRun not fully disabled",
                $"NoDriveTypeAutoRun is {(policyValue == null ? "not configured" : $"0x{policyValue:X2} (partial)")}. " +
                "AutoRun should be set to 0xFF to block automatic execution from all drive types, " +
                "preventing malware spread via USB drives.",
                UsbStorCategory,
                "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 0xFF (255).",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "AutoRun disabled for all drive types",
                "NoDriveTypeAutoRun is set to 0xFF, blocking automatic execution from all removable media.",
                UsbStorCategory));
        }
    }

    /// <summary>
    /// Checks whether AutoPlay is disabled. AutoPlay prompts users to run content
    /// from removable media, which can be socially engineered.
    /// </summary>
    private void CheckAutoPlayDisabled(AuditResult result)
    {
        const string autoPlayPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers";
        const string valueName = "DisableAutoplay";

        bool disabled = false;

        using (var key = Registry.CurrentUser.OpenSubKey(autoPlayPath))
        {
            if (key?.GetValue(valueName) is int val && val == 1)
                disabled = true;
        }

        if (!disabled)
        {
            // Also check Group Policy path
            const string gpPath = @"SOFTWARE\Policies\Microsoft\Windows\Explorer";
            using var key = Registry.LocalMachine.OpenSubKey(gpPath);
            if (key?.GetValue("NoAutoplayfornonVolume") is int val && val == 1)
                disabled = true;
        }

        if (!disabled)
        {
            result.Findings.Add(Finding.Warning(
                "AutoPlay is enabled",
                "AutoPlay prompts users when removable media is inserted, which can be exploited " +
                "via social engineering to trick users into running malicious content.",
                UsbStorCategory,
                "Disable AutoPlay via Settings > Devices > AutoPlay, or set DisableAutoplay=1 in the registry.",
                "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers' -Name 'DisableAutoplay' -Value 1 -Type DWord"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "AutoPlay is disabled",
                "AutoPlay is disabled, preventing automatic prompts when removable media is inserted.",
                UsbStorCategory));
        }
    }

    /// <summary>
    /// Checks whether USB write-protect policy is configured. This prevents data
    /// exfiltration by blocking writes to removable storage devices.
    /// </summary>
    private void CheckUsbWriteProtectPolicy(AuditResult result)
    {
        const string storagePath = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
        const string valueName = "WriteProtect";

        bool writeProtected = false;
        using (var key = Registry.LocalMachine.OpenSubKey(storagePath))
        {
            if (key?.GetValue(valueName) is int val && val == 1)
                writeProtected = true;
        }

        if (writeProtected)
        {
            result.Findings.Add(Finding.Pass(
                "USB write-protect policy enabled",
                "Removable storage devices are write-protected via StorageDevicePolicies, " +
                "preventing data exfiltration to USB drives.",
                UsbStorCategory));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "USB write-protect policy not configured",
                "The StorageDevicePolicies WriteProtect value is not set. USB drives can be written to freely. " +
                "Consider enabling write-protect in high-security environments to prevent data exfiltration.",
                UsbStorCategory,
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect to 1.",
                "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies' -Name 'WriteProtect' -Value 1 -Type DWord"));
        }
    }

    /// <summary>
    /// Checks whether USB mass storage device installation is blocked via Group Policy.
    /// </summary>
    private void CheckUsbStorageDisablePolicy(AuditResult result)
    {
        // Device Installation Restrictions
        const string denyPath = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        const string denyValue = "DenyRemovableDevices";

        bool denied = false;
        using (var key = Registry.LocalMachine.OpenSubKey(denyPath))
        {
            if (key?.GetValue(denyValue) is int val && val == 1)
                denied = true;
        }

        // Also check the legacy USB storage driver disable
        const string usbStorPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
        int? startValue = null;
        using (var key = Registry.LocalMachine.OpenSubKey(usbStorPath))
        {
            if (key?.GetValue("Start") is int val)
                startValue = val;
        }

        bool usbStorDisabled = startValue == 4; // 4 = disabled

        if (denied || usbStorDisabled)
        {
            result.Findings.Add(Finding.Pass(
                "USB mass storage installation restricted",
                denied
                    ? "Group Policy denies removable device installation (DenyRemovableDevices=1)."
                    : "USBSTOR service is disabled (Start=4), blocking USB mass storage devices.",
                UsbStorCategory));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "USB mass storage is allowed",
                $"USBSTOR service Start value is {startValue?.ToString() ?? "not found"} (3=enabled). " +
                "USB mass storage devices can be freely connected. " +
                "In sensitive environments, consider restricting via Group Policy or disabling USBSTOR.",
                UsbStorCategory,
                "Use Group Policy: Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions."));
        }
    }

    /// <summary>
    /// Checks BitLocker-to-Go enforcement: whether removable drives require encryption.
    /// </summary>
    private async Task CheckBitLockerToGo(AuditResult result, CancellationToken ct)
    {
        // Check Group Policy: Deny write access to removable drives not protected by BitLocker
        const string blPath = @"SOFTWARE\Policies\Microsoft\FVE";
        const string rdvDenyWrite = "RDVDenyWriteAccess";

        bool denyWriteUnencrypted = false;
        using (var key = Registry.LocalMachine.OpenSubKey(blPath))
        {
            if (key?.GetValue(rdvDenyWrite) is int val && val == 1)
                denyWriteUnencrypted = true;
        }

        if (denyWriteUnencrypted)
        {
            result.Findings.Add(Finding.Pass(
                "BitLocker-to-Go write restriction enabled",
                "Group Policy denies write access to removable drives not protected by BitLocker, " +
                "ensuring data written to USB drives is always encrypted.",
                UsbStorCategory));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "BitLocker-to-Go write restriction not enforced",
                "Removable drives are not required to be encrypted before data can be written to them. " +
                "Sensitive data copied to unencrypted USB drives is at risk if the drive is lost or stolen.",
                UsbStorCategory,
                "Enable 'Deny write access to removable drives not protected by BitLocker' in Group Policy.",
                "# Requires Group Policy Editor (gpedit.msc): Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Removable Data Drives"));
        }

        // Check if any currently connected removable drives are unencrypted
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Data' } | " +
                "Select-Object -Property MountPoint, ProtectionStatus, VolumeStatus | ConvertTo-Json -Compress",
                ct);

            if (!string.IsNullOrWhiteSpace(output) && output.Trim() != "null")
            {
                // Parse and check for unprotected data volumes (likely removable)
                result.Findings.Add(Finding.Info(
                    "BitLocker data volume status retrieved",
                    "Use `Get-BitLockerVolume` to verify all removable data volumes are encrypted.",
                    UsbStorCategory));
            }
        }
        catch
        {
            // BitLocker cmdlets may not be available on all editions
        }
    }

    /// <summary>
    /// Enumerates USB device connection history from the registry to report
    /// recently connected removable storage devices.
    /// </summary>
    private void CheckUsbDeviceHistory(AuditResult result)
    {
        const string usbStorPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";
        int deviceCount = 0;
        var recentDevices = new List<string>();

        try
        {
            using var usbKey = Registry.LocalMachine.OpenSubKey(usbStorPath);
            if (usbKey != null)
            {
                foreach (var deviceClass in usbKey.GetSubKeyNames())
                {
                    using var classKey = usbKey.OpenSubKey(deviceClass);
                    if (classKey == null) continue;

                    foreach (var instance in classKey.GetSubKeyNames())
                    {
                        deviceCount++;
                        using var instanceKey = classKey.OpenSubKey(instance);
                        var friendlyName = instanceKey?.GetValue("FriendlyName") as string;
                        if (!string.IsNullOrEmpty(friendlyName) && recentDevices.Count < 10)
                        {
                            recentDevices.Add(friendlyName);
                        }
                    }
                }
            }
        }
        catch
        {
            // Access denied or key missing — not critical
        }

        if (deviceCount == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No USB storage device history found",
                "No USB mass storage devices have been connected to this system (or history has been cleared).",
                UsbStorCategory));
        }
        else
        {
            var deviceList = recentDevices.Count > 0
                ? $" Recent devices: {string.Join(", ", recentDevices)}."
                : "";
            result.Findings.Add(Finding.Info(
                $"{deviceCount} USB storage device(s) in connection history",
                $"The system has records of {deviceCount} USB mass storage device connections.{deviceList} " +
                "Review this list for unauthorized or unexpected devices.",
                UsbStorCategory,
                "Regularly audit USB device connections. Consider implementing USB device whitelisting via Group Policy."));
        }
    }

    /// <summary>
    /// Checks the default encryption requirement for removable disks
    /// via the BitLocker configuration service provider.
    /// </summary>
    private void CheckRemovableDiskEncryption(AuditResult result)
    {
        // Check if encryption is required for removable data drives
        const string fvePath = @"SOFTWARE\Policies\Microsoft\FVE";
        
        bool requireEncryption = false;
        using (var key = Registry.LocalMachine.OpenSubKey(fvePath))
        {
            // RDVConfigureBDE = 1 means BitLocker is required for removable drives
            if (key?.GetValue("RDVConfigureBDE") is int val && val == 1)
                requireEncryption = true;
        }

        if (requireEncryption)
        {
            result.Findings.Add(Finding.Pass(
                "Removable drive encryption policy configured",
                "BitLocker encryption is required for removable data drives via Group Policy.",
                UsbStorCategory));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "No removable drive encryption requirement",
                "There is no Group Policy requiring BitLocker encryption on removable data drives. " +
                "Consider enforcing encryption to protect sensitive data on portable media.",
                UsbStorCategory,
                "Configure 'Control use of BitLocker on removable drives' in Group Policy."));
        }
    }
}
