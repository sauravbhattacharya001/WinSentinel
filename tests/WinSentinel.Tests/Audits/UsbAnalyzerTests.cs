using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.UsbAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="UsbAnalyzer"/>.
///
/// <see cref="UsbAuditTests"/> already exercises the module end-to-end against the
/// live system (where every value is whatever the host happens to have); this suite
/// targets the analyzer's own surface directly with synthetic <see cref="UsbState"/>
/// instances so every classification threshold (AutoRun must be exactly 0xFF, USBSTOR
/// Start=4 means disabled, the device-history info-vs-pass split, the BitLocker-to-Go
/// and removable-encryption policy gates) is pinned without reading the registry or
/// running BitLocker cmdlets.
/// </summary>
public class UsbAnalyzerTests
{
    // ── Fixtures ──────────────────────────────────────────────────────────────

    /// <summary>A fully-hardened removable-media posture (every check should Pass).</summary>
    private static UsbState SecureState() => new()
    {
        NoDriveTypeAutoRun = 0xFF,
        AutoPlayDisabled = true,
        UsbWriteProtected = true,
        DenyRemovableDevices = true,
        UsbStorStartValue = UsbStorDisabledStart,
        RdvDenyWriteAccess = true,
        BitLockerDataVolumeStatusAvailable = false,
        UsbDeviceCount = 0,
        RequireRemovableEncryption = true,
    };

    /// <summary>A wide-open posture (nothing configured, AutoPlay on, devices present).</summary>
    private static UsbState InsecureState() => new()
    {
        NoDriveTypeAutoRun = null,
        AutoPlayDisabled = false,
        UsbWriteProtected = false,
        DenyRemovableDevices = false,
        UsbStorStartValue = 3,
        RdvDenyWriteAccess = false,
        BitLockerDataVolumeStatusAvailable = true,
        UsbDeviceCount = 3,
        RecentDeviceNames = new() { "SanDisk Cruzer USB Device", "Kingston DataTraveler" },
        RequireRemovableEncryption = false,
    };

    private static Finding Single(Func<UsbState, Finding> check, UsbState state) => check(state);

    // ── Aggregate ─────────────────────────────────────────────────────────────

    [Fact]
    public void Analyze_NullState_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => UsbAnalyzer.Analyze(null!));
    }

    [Fact]
    public void Analyze_SecureState_AllPass()
    {
        var findings = UsbAnalyzer.Analyze(SecureState());

        Assert.All(findings, f => Assert.Equal(Severity.Pass, f.Severity));
        Assert.Equal(0, findings.Count(f => f.Severity == Severity.Warning));
    }

    [Fact]
    public void Analyze_SecureState_EmitsSevenFindings_NoBitLockerInfo()
    {
        // BitLockerDataVolumeStatusAvailable=false → the optional info is suppressed,
        // so AutoRun, AutoPlay, WriteProtect, StorageDisable, BitLocker-to-Go,
        // DeviceHistory, RemovableEncryption = 7.
        var findings = UsbAnalyzer.Analyze(SecureState());
        Assert.Equal(7, findings.Count);
    }

    [Fact]
    public void Analyze_WhenBitLockerStatusAvailable_EmitsEightFindings()
    {
        var state = SecureState();
        state.BitLockerDataVolumeStatusAvailable = true;
        var findings = UsbAnalyzer.Analyze(state);
        Assert.Equal(8, findings.Count);
    }

    [Fact]
    public void Analyze_AllFindings_HaveUsbCategoryAndContent()
    {
        var findings = UsbAnalyzer.Analyze(InsecureState());

        Assert.NotEmpty(findings);
        Assert.All(findings, f =>
        {
            Assert.Equal("USB", f.Category);
            Assert.False(string.IsNullOrWhiteSpace(f.Title));
            Assert.False(string.IsNullOrWhiteSpace(f.Description));
        });
    }

    [Fact]
    public void Analyze_PreservesHistoricalOrder()
    {
        // The module historically emitted: AutoRun, AutoPlay, WriteProtect,
        // StorageDisable, BitLocker-to-Go, [BitLocker info], DeviceHistory,
        // RemovableEncryption. Pin that order.
        var state = InsecureState(); // BitLocker info present
        var titles = UsbAnalyzer.Analyze(state).Select(f => f.Title).ToList();

        Assert.Equal(8, titles.Count);
        Assert.Contains("AutoRun", titles[0]);
        Assert.Contains("AutoPlay", titles[1]);
        Assert.Contains("write-protect", titles[2]);
        Assert.Contains("USB mass storage", titles[3]);
        Assert.Contains("BitLocker-to-Go", titles[4]);
        Assert.Contains("BitLocker data volume status", titles[5]);
        Assert.Contains("connection history", titles[6]);
        Assert.Contains("removable drive encryption", titles[7], StringComparison.OrdinalIgnoreCase);
    }

    // ── AutoRun ───────────────────────────────────────────────────────────────

    [Fact]
    public void AutoRun_ExactlyFF_Passes()
    {
        var f = Single(CheckAutoRun, new UsbState { NoDriveTypeAutoRun = 0xFF });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("0xFF", f.Description);
    }

    [Fact]
    public void AutoRun_NotConfigured_WarnsWithNotConfiguredWording()
    {
        var f = Single(CheckAutoRun, new UsbState { NoDriveTypeAutoRun = null });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("not configured", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x91)] // common "removable + network" partial mask
    [InlineData(0xFE)] // one bit short of full
    public void AutoRun_PartialMask_WarnsWithHexDetail(int value)
    {
        var f = Single(CheckAutoRun, new UsbState { NoDriveTypeAutoRun = value });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("(partial)", f.Description);
        Assert.Contains($"0x{value:X2}", f.Description);
    }

    // ── AutoPlay ──────────────────────────────────────────────────────────────

    [Fact]
    public void AutoPlay_Disabled_Passes()
    {
        var f = Single(CheckAutoPlay, new UsbState { AutoPlayDisabled = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void AutoPlay_Enabled_Warns()
    {
        var f = Single(CheckAutoPlay, new UsbState { AutoPlayDisabled = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("social engineering", f.Description);
    }

    // ── Write-protect ─────────────────────────────────────────────────────────

    [Fact]
    public void WriteProtect_Enabled_Passes()
    {
        var f = Single(CheckWriteProtect, new UsbState { UsbWriteProtected = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void WriteProtect_NotConfigured_IsInfoNotWarning()
    {
        // Opt-in hardening control → Info, never Warning (matches the original module).
        var f = Single(CheckWriteProtect, new UsbState { UsbWriteProtected = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    // ── USB mass-storage installation restriction ─────────────────────────────

    [Fact]
    public void StorageDisable_DenyRemovableDevices_PassesWithGpoWording()
    {
        var f = Single(CheckUsbStorageDisablePolicy, new UsbState
        {
            DenyRemovableDevices = true,
            UsbStorStartValue = 3, // even when USBSTOR is enabled, the deny policy wins
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("DenyRemovableDevices=1", f.Description);
    }

    [Fact]
    public void StorageDisable_UsbStorDisabled_PassesWithServiceWording()
    {
        var f = Single(CheckUsbStorageDisablePolicy, new UsbState
        {
            DenyRemovableDevices = false,
            UsbStorStartValue = UsbStorDisabledStart, // 4
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Start=4", f.Description);
    }

    [Fact]
    public void StorageDisable_NeitherRestriction_IsInfo()
    {
        var f = Single(CheckUsbStorageDisablePolicy, new UsbState
        {
            DenyRemovableDevices = false,
            UsbStorStartValue = 3,
        });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("3", f.Description);
    }

    [Fact]
    public void StorageDisable_UsbStorStartNotFound_IsInfoWithNotFound()
    {
        var f = Single(CheckUsbStorageDisablePolicy, new UsbState
        {
            DenyRemovableDevices = false,
            UsbStorStartValue = null,
        });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("not found", f.Description);
    }

    // ── BitLocker-to-Go write restriction ─────────────────────────────────────

    [Fact]
    public void BitLockerToGo_DenyWriteEnforced_Passes()
    {
        var f = Single(CheckBitLockerToGoWriteRestriction, new UsbState { RdvDenyWriteAccess = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BitLockerToGo_NotEnforced_Warns()
    {
        var f = Single(CheckBitLockerToGoWriteRestriction, new UsbState { RdvDenyWriteAccess = false });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("lost or stolen", f.Description);
    }

    // ── BitLocker data-volume status (optional info) ──────────────────────────

    [Fact]
    public void BitLockerDataVolumeStatus_Available_EmitsInfo()
    {
        var f = CheckBitLockerDataVolumeStatus(new UsbState { BitLockerDataVolumeStatusAvailable = true });
        Assert.NotNull(f);
        Assert.Equal(Severity.Info, f!.Severity);
    }

    [Fact]
    public void BitLockerDataVolumeStatus_Unavailable_EmitsNothing()
    {
        var f = CheckBitLockerDataVolumeStatus(new UsbState { BitLockerDataVolumeStatusAvailable = false });
        Assert.Null(f);
    }

    // ── Device history ────────────────────────────────────────────────────────

    [Fact]
    public void DeviceHistory_NoDevices_Passes()
    {
        var f = Single(CheckDeviceHistory, new UsbState { UsbDeviceCount = 0 });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("No USB", f.Title);
    }

    [Fact]
    public void DeviceHistory_WithDevices_IsInfoAndListsNames()
    {
        var f = Single(CheckDeviceHistory, new UsbState
        {
            UsbDeviceCount = 2,
            RecentDeviceNames = new() { "SanDisk Cruzer", "Kingston DT" },
        });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("2 USB storage device(s)", f.Title);
        Assert.Contains("SanDisk Cruzer", f.Description);
        Assert.Contains("Kingston DT", f.Description);
        Assert.Contains("Recent devices:", f.Description);
    }

    [Fact]
    public void DeviceHistory_CountWithoutNames_OmitsRecentList()
    {
        // Count can exceed the captured names (e.g. unnamed instances); no "Recent devices:" then.
        var f = Single(CheckDeviceHistory, new UsbState
        {
            UsbDeviceCount = 5,
            RecentDeviceNames = new(),
        });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("5 USB mass storage device connections.", f.Description);
        Assert.DoesNotContain("Recent devices:", f.Description);
    }

    [Fact]
    public void DeviceHistory_BlankNames_AreFilteredOut()
    {
        var f = Single(CheckDeviceHistory, new UsbState
        {
            UsbDeviceCount = 3,
            RecentDeviceNames = new() { "", "  ", "Real Device" },
        });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Recent devices: Real Device.", f.Description);
        // No leading comma / empty entries.
        Assert.DoesNotContain(", ,", f.Description);
    }

    [Fact]
    public void DeviceHistory_CapsListedNamesAtTen()
    {
        var names = Enumerable.Range(1, 25).Select(i => $"Device{i:00}").ToList();
        var f = Single(CheckDeviceHistory, new UsbState { UsbDeviceCount = 25, RecentDeviceNames = names });

        // Count still reports all 25, but at most 10 names are surfaced.
        Assert.Contains("25 USB mass storage device connections.", f.Description);
        Assert.Contains("Device10", f.Description);
        Assert.DoesNotContain("Device11", f.Description);
    }

    // ── Removable-disk encryption requirement ─────────────────────────────────

    [Fact]
    public void RemovableEncryption_Required_Passes()
    {
        var f = Single(CheckRemovableDiskEncryption, new UsbState { RequireRemovableEncryption = true });
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void RemovableEncryption_NotRequired_IsInfo()
    {
        var f = Single(CheckRemovableDiskEncryption, new UsbState { RequireRemovableEncryption = false });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Group Policy", f.Description);
    }

    // ── Constants sanity ──────────────────────────────────────────────────────

    [Fact]
    public void Constants_HaveExpectedValues()
    {
        Assert.Equal(0xFF, AutoRunFullyDisabledValue);
        Assert.Equal(4, UsbStorDisabledStart);
        Assert.Equal(10, MaxRecentDevicesListed);
        Assert.Equal("USB", UsbAnalyzer.Category);
    }
}
