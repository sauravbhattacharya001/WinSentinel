using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="UsbAudit"/> module.
///
/// Every USB / removable-media decision lives here - the rules that turn collected
/// raw state (the AutoRun <c>NoDriveTypeAutoRun</c> policy, AutoPlay toggles, the
/// <c>StorageDevicePolicies\WriteProtect</c> flag, USB mass-storage installation
/// restrictions, BitLocker-to-Go enforcement, the <c>USBSTOR</c> enumeration history
/// and removable-drive encryption policy) into <see cref="Finding"/> objects.
///
/// Nothing here touches the registry, PowerShell, WMI, the clock or the console, so
/// every threshold (AutoRun must be exactly <c>0xFF</c>, USBSTOR <c>Start=4</c> means
/// disabled, the device-history info-vs-pass split, ...) can be unit-tested directly
/// with synthetic <see cref="UsbState"/> instances. <see cref="UsbAudit"/> owns only
/// the collection of raw data and delegates every decision to this class.
///
/// Mirrors the established <see cref="NetworkPostureAnalyzer"/> /
/// <see cref="PowerShellSecurityAnalyzer"/> / <see cref="BrowserSecurityAnalyzer"/> /
/// <see cref="EncryptionAnalyzer"/> / <see cref="EventLogAnalyzer"/> /
/// <see cref="IdentityCredentialAnalyzer"/> pattern.
/// </summary>
public static class UsbAnalyzer
{
    /// <summary>Category label shared with <see cref="UsbAudit"/>.</summary>
    public const string Category = "USB";

    /// <summary>The value <c>NoDriveTypeAutoRun</c> must hold to fully disable AutoRun.</summary>
    public const int AutoRunFullyDisabledValue = 0xFF;

    /// <summary>The <c>USBSTOR</c> service <c>Start</c> value meaning "disabled".</summary>
    public const int UsbStorDisabledStart = 4;

    /// <summary>Maximum number of recent device friendly-names surfaced in the history finding.</summary>
    public const int MaxRecentDevicesListed = 10;

    // ──────────────────────────────────────────────────────────────────────
    // State DTO
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Data transfer object for the USB / removable-media environment. All checks
    /// operate on this record so they can be unit-tested without reading the registry
    /// or running BitLocker cmdlets.
    ///
    /// Nullable <see cref="int"/> fields model "policy not configured / value absent";
    /// nullable <see cref="bool"/> fields model "value could not be read".
    /// </summary>
    public sealed class UsbState
    {
        /// <summary>
        /// <c>NoDriveTypeAutoRun</c> (HKLM machine policy, else HKCU user policy).
        /// <c>null</c> = not configured. <c>0xFF</c> = AutoRun fully disabled.
        /// </summary>
        public int? NoDriveTypeAutoRun { get; set; }

        /// <summary>
        /// True when AutoPlay is disabled via either <c>DisableAutoplay=1</c> (HKCU)
        /// or <c>NoAutoplayfornonVolume=1</c> (HKLM Group Policy).
        /// </summary>
        public bool AutoPlayDisabled { get; set; }

        /// <summary><c>StorageDevicePolicies\WriteProtect == 1</c>.</summary>
        public bool UsbWriteProtected { get; set; }

        /// <summary>
        /// Device Installation Restrictions <c>DenyRemovableDevices == 1</c>.
        /// </summary>
        public bool DenyRemovableDevices { get; set; }

        /// <summary>
        /// <c>USBSTOR</c> service <c>Start</c> value (3 = enabled, 4 = disabled).
        /// <c>null</c> = value not found.
        /// </summary>
        public int? UsbStorStartValue { get; set; }

        /// <summary>
        /// BitLocker-to-Go: <c>FVE\RDVDenyWriteAccess == 1</c> (deny write to
        /// unencrypted removable drives).
        /// </summary>
        public bool RdvDenyWriteAccess { get; set; }

        /// <summary>
        /// True when <c>Get-BitLockerVolume</c> returned a non-null payload for the
        /// data volumes (so the info finding about verifying them is emitted).
        /// </summary>
        public bool BitLockerDataVolumeStatusAvailable { get; set; }

        /// <summary>
        /// Total number of USB mass-storage device instances found under
        /// <c>USBSTOR</c> enumeration.
        /// </summary>
        public int UsbDeviceCount { get; set; }

        /// <summary>Friendly names of recently connected USB storage devices (capped at collection time).</summary>
        public List<string> RecentDeviceNames { get; set; } = new();

        /// <summary>BitLocker required for removable drives: <c>FVE\RDVConfigureBDE == 1</c>.</summary>
        public bool RequireRemovableEncryption { get; set; }

        /// <summary>
        /// Removable Storage Access policy denies ALL removable storage classes for
        /// write (or read+write): <c>RemovableStorageDevices\Deny_All == 1</c>.
        /// This is the only control that also covers WPD/MTP devices (phones, cameras,
        /// media players), which enumerate outside <c>USBSTOR</c> and so bypass the
        /// mass-storage / <c>USBSTOR</c> restrictions entirely.
        /// </summary>
        public bool DenyAllRemovableStorage { get; set; }

        /// <summary>
        /// Whether the machine has WPD-class removable devices whose write access is
        /// specifically denied via the WPD device-class GUID
        /// (<c>{6AC27878-A6FA-4155-BA85-F98F491D4F33}\Deny_Write == 1</c>). This is a
        /// narrower fallback to <see cref="DenyAllRemovableStorage"/>.
        /// </summary>
        public bool WpdWriteDenied { get; set; }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Aggregate entry point
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs every USB / removable-media check against <paramref name="state"/> and
    /// returns the findings in the same order <see cref="UsbAudit"/> historically
    /// emitted them. Pure - no I/O.
    /// </summary>
    public static List<Finding> Analyze(UsbState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>
        {
            CheckAutoRun(state),
            CheckAutoPlay(state),
            CheckWriteProtect(state),
            CheckUsbStorageDisablePolicy(state),
            CheckBitLockerToGoWriteRestriction(state),
        };

        var blInfo = CheckBitLockerDataVolumeStatus(state);
        if (blInfo != null) findings.Add(blInfo);

        findings.Add(CheckDeviceHistory(state));
        findings.Add(CheckRemovableDiskEncryption(state));
        findings.Add(CheckWpdMtpRestriction(state));
        return findings;
    }

    // ── AutoRun ───────────────────────────────────────────────────────────────

    /// <summary>
    /// AutoRun must be fully disabled for every drive type (<c>NoDriveTypeAutoRun ==
    /// 0xFF</c>); anything else (unset or a partial mask) is a Warning.
    /// </summary>
    public static Finding CheckAutoRun(UsbState state)
    {
        if (state.NoDriveTypeAutoRun == AutoRunFullyDisabledValue)
        {
            return Finding.Pass(
                "AutoRun disabled for all drive types",
                "NoDriveTypeAutoRun is set to 0xFF, blocking automatic execution from all removable media.",
                Category);
        }

        var detail = state.NoDriveTypeAutoRun == null
            ? "not configured"
            : $"0x{state.NoDriveTypeAutoRun:X2} (partial)";

        return Finding.Warning(
            "AutoRun not fully disabled",
            $"NoDriveTypeAutoRun is {detail}. " +
            "AutoRun should be set to 0xFF to block automatic execution from all drive types, " +
            "preventing malware spread via USB drives.",
            Category,
            "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 0xFF (255).",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord");
    }

    // ── AutoPlay ──────────────────────────────────────────────────────────────

    /// <summary>
    /// AutoPlay prompts on insertion are a social-engineering vector; emits Pass when
    /// disabled, Warning otherwise.
    /// </summary>
    public static Finding CheckAutoPlay(UsbState state)
    {
        if (state.AutoPlayDisabled)
        {
            return Finding.Pass(
                "AutoPlay is disabled",
                "AutoPlay is disabled, preventing automatic prompts when removable media is inserted.",
                Category);
        }

        return Finding.Warning(
            "AutoPlay is enabled",
            "AutoPlay prompts users when removable media is inserted, which can be exploited " +
            "via social engineering to trick users into running malicious content.",
            Category,
            "Disable AutoPlay via Settings > Devices > AutoPlay, or set DisableAutoplay=1 in the registry.",
            "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers' -Name 'DisableAutoplay' -Value 1 -Type DWord");
    }

    // ── USB write-protect ─────────────────────────────────────────────────────

    /// <summary>
    /// Write-protect blocks exfiltration to USB. It is an opt-in hardening control,
    /// so the "not configured" state is Info (not a Warning), matching the original
    /// module.
    /// </summary>
    public static Finding CheckWriteProtect(UsbState state)
    {
        if (state.UsbWriteProtected)
        {
            return Finding.Pass(
                "USB write-protect policy enabled",
                "Removable storage devices are write-protected via StorageDevicePolicies, " +
                "preventing data exfiltration to USB drives.",
                Category);
        }

        return Finding.Info(
            "USB write-protect policy not configured",
            "The StorageDevicePolicies WriteProtect value is not set. USB drives can be written to freely. " +
            "Consider enabling write-protect in high-security environments to prevent data exfiltration.",
            Category,
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect to 1.",
            // Single reg.exe command: creates the StorageDevicePolicies key if missing
            // and sets WriteProtect atomically. The old "New-Item ... | Out-Null;
            // Set-ItemProperty ..." form was blocked by InputSanitizer.CheckDangerousCommand
            // (semicolon chaining), so the Fix action could never run.
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\" /v WriteProtect /t REG_DWORD /d 1 /f");
    }

    // ── USB mass-storage installation restriction ─────────────────────────────

    /// <summary>
    /// Passes when removable-device installation is denied by Group Policy OR the
    /// legacy <c>USBSTOR</c> service is disabled (<c>Start=4</c>); otherwise Info that
    /// USB mass storage is freely allowed.
    /// </summary>
    public static Finding CheckUsbStorageDisablePolicy(UsbState state)
    {
        bool usbStorDisabled = state.UsbStorStartValue == UsbStorDisabledStart;

        if (state.DenyRemovableDevices || usbStorDisabled)
        {
            return Finding.Pass(
                "USB mass storage installation restricted",
                state.DenyRemovableDevices
                    ? "Group Policy denies removable device installation (DenyRemovableDevices=1)."
                    : "USBSTOR service is disabled (Start=4), blocking USB mass storage devices.",
                Category);
        }

        return Finding.Info(
            "USB mass storage is allowed",
            $"USBSTOR service Start value is {state.UsbStorStartValue?.ToString() ?? "not found"} (3=enabled). " +
            "USB mass storage devices can be freely connected. " +
            "In sensitive environments, consider restricting via Group Policy or disabling USBSTOR.",
            Category,
            "Use Group Policy: Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions.");
    }

    // ── BitLocker-to-Go write restriction ─────────────────────────────────────

    /// <summary>
    /// Whether write access to removable drives not protected by BitLocker is denied.
    /// Pass when enforced, Warning otherwise.
    /// </summary>
    public static Finding CheckBitLockerToGoWriteRestriction(UsbState state)
    {
        if (state.RdvDenyWriteAccess)
        {
            return Finding.Pass(
                "BitLocker-to-Go write restriction enabled",
                "Group Policy denies write access to removable drives not protected by BitLocker, " +
                "ensuring data written to USB drives is always encrypted.",
                Category);
        }

        return Finding.Warning(
            "BitLocker-to-Go write restriction not enforced",
            "Removable drives are not required to be encrypted before data can be written to them. " +
            "Sensitive data copied to unencrypted USB drives is at risk if the drive is lost or stolen.",
            Category,
            "Enable 'Deny write access to removable drives not protected by BitLocker' in Group Policy.",
            "# Requires Group Policy Editor (gpedit.msc): Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Removable Data Drives");
    }

    /// <summary>
    /// Optional info finding emitted only when the live BitLocker data-volume status
    /// was successfully retrieved (the original module emitted nothing when the
    /// cmdlet was unavailable or returned <c>null</c>).
    /// </summary>
    public static Finding? CheckBitLockerDataVolumeStatus(UsbState state)
    {
        if (!state.BitLockerDataVolumeStatusAvailable) return null;

        return Finding.Info(
            "BitLocker data volume status retrieved",
            "Use `Get-BitLockerVolume` to verify all removable data volumes are encrypted.",
            Category);
    }

    // ── USB device history ─────────────────────────────────────────────────────

    /// <summary>
    /// Reports the USBSTOR connection history. Zero devices is a Pass (clean / cleared
    /// history); any devices is Info with up to <see cref="MaxRecentDevicesListed"/>
    /// friendly names to review.
    /// </summary>
    public static Finding CheckDeviceHistory(UsbState state)
    {
        if (state.UsbDeviceCount == 0)
        {
            return Finding.Pass(
                "No USB storage device history found",
                "No USB mass storage devices have been connected to this system (or history has been cleared).",
                Category);
        }

        var listed = state.RecentDeviceNames
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Take(MaxRecentDevicesListed)
            .ToList();

        var deviceList = listed.Count > 0
            ? $" Recent devices: {string.Join(", ", listed)}."
            : "";

        return Finding.Info(
            $"{state.UsbDeviceCount} USB storage device(s) in connection history",
            $"The system has records of {state.UsbDeviceCount} USB mass storage device connections.{deviceList} " +
            "Review this list for unauthorized or unexpected devices.",
            Category,
            "Regularly audit USB device connections. Consider implementing USB device whitelisting via Group Policy.");
    }

    // ── Removable-disk encryption requirement ─────────────────────────────────

    /// <summary>
    /// Whether BitLocker is required for removable data drives
    /// (<c>FVE\RDVConfigureBDE == 1</c>). Pass when configured, Info otherwise.
    /// </summary>
    public static Finding CheckRemovableDiskEncryption(UsbState state)
    {
        if (state.RequireRemovableEncryption)
        {
            return Finding.Pass(
                "Removable drive encryption policy configured",
                "BitLocker encryption is required for removable data drives via Group Policy.",
                Category);
        }

        return Finding.Info(
            "No removable drive encryption requirement",
            "There is no Group Policy requiring BitLocker encryption on removable data drives. " +
            "Consider enforcing encryption to protect sensitive data on portable media.",
            Category,
            "Configure 'Control use of BitLocker on removable drives' in Group Policy.");
    }

    // ── WPD / MTP (phones, cameras, media players) restriction ────────────────

    /// <summary>
    /// WPD/MTP devices (phones, cameras, portable media players) transfer files over
    /// the Media Transfer Protocol and enumerate <em>outside</em> <c>USBSTOR</c>, so
    /// they are NOT covered by the mass-storage / <c>USBSTOR</c> restrictions checked
    /// above — a well-known data-exfiltration gap (plug in a phone, drag files off).
    /// The only policy that closes it is the Removable Storage Access node:
    /// <c>Deny_All=1</c> (all classes) or, more narrowly, the WPD device-class
    /// <c>Deny_Write=1</c>. Passes when either is enforced; Info otherwise.
    /// </summary>
    public static Finding CheckWpdMtpRestriction(UsbState state)
    {
        if (state.DenyAllRemovableStorage || state.WpdWriteDenied)
        {
            return Finding.Pass(
                "WPD/MTP portable devices restricted",
                state.DenyAllRemovableStorage
                    ? "Removable Storage Access policy denies all removable storage classes (Deny_All=1), " +
                      "which also blocks WPD/MTP devices such as phones, cameras and media players."
                    : "Write access to WPD portable devices is denied via the WPD device-class policy " +
                      "(Deny_Write=1), blocking data transfer to phones, cameras and media players.",
                Category);
        }

        return Finding.Info(
            "WPD/MTP portable devices not restricted",
            "Phones, cameras and portable media players connect over MTP/WPD and enumerate outside USBSTOR, " +
            "so they are NOT blocked by USB mass-storage or USBSTOR restrictions. A user can copy sensitive " +
            "data onto a phone even when USB drives are otherwise locked down. Consider denying WPD/MTP write " +
            "access via the Removable Storage Access Group Policy.",
            Category,
            "Enable 'Removable Storage Access: All Removable Storage classes: Deny all access' " +
            "(or the WPD-class 'Deny write access') under Computer Configuration > Administrative Templates > " +
            "System > Removable Storage Access.");
    }
}
