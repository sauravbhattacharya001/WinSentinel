using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.BluetoothAudit;

namespace WinSentinel.Tests.Audits;

public class BluetoothAuditTests
{
    private readonly BluetoothAudit _audit;

    public BluetoothAuditTests()
    {
        _audit = new BluetoothAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Bluetooth Security Audit",
        Category = "Bluetooth"
    };

    private static BluetoothState MakeSecureState() => new()
    {
        RadioPresent = true,
        RadioEnabled = false,
        Discoverable = false,
        Connectable = false,
        AdapterName = "Intel Wireless Bluetooth",
        NameMatchesHostname = false,
        BluetoothServiceState = ServiceRunState.Disabled,
        PairedDevices = new List<PairedDevice>(),
        ExposedServices = new List<string>(),
        SspSupported = true,
        EncryptionEnforced = true,
        DriverVersion = "22.180.0.4",
        DriverAgeDays = 60,
    };

    private static BluetoothState MakeInsecureState() => new()
    {
        RadioPresent = true,
        RadioEnabled = true,
        Discoverable = true,
        Connectable = true,
        AdapterName = "DESKTOP-ABC123",
        NameMatchesHostname = true,
        BluetoothServiceState = ServiceRunState.Running,
        PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Unknown Device", Address = "AA:BB:CC:DD:EE:FF", Authenticated = false, DeviceType = "Uncategorized", DaysSinceLastUse = 180 },
            new() { Name = "", Address = "11:22:33:44:55:66", Authenticated = true, DeviceType = "Audio" },
        },
        ExposedServices = new List<string> { "OBEX Object Push", "Serial Port", "Audio Sink" },
        SspSupported = false,
        EncryptionEnforced = false,
        DriverVersion = "18.1.0.1",
        DriverAgeDays = 900,
    };

    // ── Module metadata ──

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Bluetooth Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("Bluetooth", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ── No radio ──

    [Fact]
    public void NoRadio_SinglePassFinding()
    {
        var state = new BluetoothState { RadioPresent = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Single(result.Findings);
        Assert.Equal(Severity.Pass, result.Findings[0].Severity);
        Assert.Contains("No Bluetooth Radio", result.Findings[0].Title);
    }

    // ── Radio enabled/disabled ──

    [Fact]
    public void RadioEnabled_InfoFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Radio Enabled" && f.Severity == Severity.Info);
    }

    [Fact]
    public void RadioDisabled_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Radio Disabled" && f.Severity == Severity.Pass);
    }

    // ── Discoverable mode ──

    [Fact]
    public void Discoverable_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.Discoverable = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Discoverable Mode Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void NotDiscoverable_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.Discoverable = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Not Discoverable" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void DiscoverableAndConnectable_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.Discoverable = true;
        state.Connectable = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Connectable While Discoverable" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void DiscoverableButNotConnectable_NoConnectableWarning()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.Discoverable = true;
        state.Connectable = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title == "Bluetooth Connectable While Discoverable");
    }

    // ── Adapter name ──

    [Fact]
    public void AdapterNameLeaksHostname_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.AdapterName = "DESKTOP-ABC123";
        state.NameMatchesHostname = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Adapter Name Reveals Hostname" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AdapterNameSafe_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.AdapterName = "Intel Wireless Bluetooth";
        state.NameMatchesHostname = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Name Does Not Leak Hostname" && f.Severity == Severity.Pass);
    }

    // ── Bluetooth service state ──

    [Fact]
    public void ServiceRunningWithoutRadio_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = false;
        state.BluetoothServiceState = ServiceRunState.Running;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Service Running Without Radio" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void ServiceDisabled_PassFinding()
    {
        var state = MakeSecureState();
        state.BluetoothServiceState = ServiceRunState.Disabled;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Service Disabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void ServiceRunningWithRadio_InfoFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.BluetoothServiceState = ServiceRunState.Running;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Service Running" && f.Severity == Severity.Info);
    }

    // ── Paired devices ──

    [Fact]
    public void NoPairedDevices_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "No Paired Devices" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void PairedDevices_InfoWithCount()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Mouse", Authenticated = true, DeviceType = "Peripheral" },
            new() { Name = "Keyboard", Authenticated = true, DeviceType = "Peripheral" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "2 Paired Device(s)" && f.Severity == Severity.Info);
    }

    [Fact]
    public void UnauthenticatedDevice_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Rogue", Address = "AA:BB:CC:DD:EE:FF", Authenticated = false, DeviceType = "Audio" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Unauthenticated") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AllDevicesAuthenticated_NoUnauthWarning()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Mouse", Authenticated = true, DeviceType = "Peripheral" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Unauthenticated"));
    }

    [Fact]
    public void StaleDevice_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "OldHeadset", Authenticated = true, DeviceType = "Audio", DaysSinceLastUse = 120 },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Stale") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void RecentDevice_NoStaleWarning()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Mouse", Authenticated = true, DeviceType = "Peripheral", DaysSinceLastUse = 5 },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Stale"));
    }

    [Fact]
    public void SuspiciousDeviceType_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "WeirdThing", Authenticated = true, DeviceType = "Uncategorized" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Suspicious Device Type") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void NormalDeviceType_NoSuspiciousWarning()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Mouse", Authenticated = true, DeviceType = "Peripheral" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Suspicious Device Type"));
    }

    [Fact]
    public void UnnamedDevice_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "", Address = "11:22:33:44:55:66", Authenticated = true, DeviceType = "Audio" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Unnamed") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AllDevicesNamed_NoUnnamedWarning()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Mouse", Authenticated = true, DeviceType = "Peripheral" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Unnamed"));
    }

    // ── Exposed services ──

    [Fact]
    public void RiskyServices_WarningFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.ExposedServices = new List<string> { "OBEX Object Push", "Serial Port" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Risky Bluetooth Service") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SafeServices_InfoFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.ExposedServices = new List<string> { "Audio Sink", "Hands-Free" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Bluetooth Service(s) Active") && f.Severity == Severity.Info);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Risky"));
    }

    [Fact]
    public void NoServices_NoServiceFindings()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.ExposedServices = new List<string>();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Service(s) Exposed") || f.Title.Contains("Service(s) Active"));
    }

    [Fact]
    public void MixedServices_BothRiskyAndSafeFindings()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.ExposedServices = new List<string> { "OBEX File Transfer", "Audio Sink", "Hands-Free" };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Risky Bluetooth Service"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Bluetooth Service(s) Active"));
    }

    // ── Authentication ──

    [Fact]
    public void NoSsp_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.SspSupported = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Secure Simple Pairing Not Supported" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void SspSupported_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.SspSupported = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Secure Simple Pairing Supported" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void EncryptionNotEnforced_CriticalFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.EncryptionEnforced = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Encryption Not Enforced" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void EncryptionEnforced_PassFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.EncryptionEnforced = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Encryption Enforced" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void RadioDisabled_NoAuthChecks()
    {
        var state = MakeSecureState();
        state.RadioEnabled = false;
        state.SspSupported = false;
        state.EncryptionEnforced = false;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Secure Simple Pairing"));
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Encryption"));
    }

    // ── Driver age ──

    [Fact]
    public void DriverOld_WarningFinding()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 900;
        state.DriverVersion = "18.1.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Outdated" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void DriverAging_InfoFinding()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 400;
        state.DriverVersion = "20.0.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Aging" && f.Severity == Severity.Info);
    }

    [Fact]
    public void DriverRecent_PassFinding()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 60;
        state.DriverVersion = "22.180.0.4";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Up to Date" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void NoDriverAge_NoDriverFindings()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Driver"));
    }

    // ── Comprehensive scenarios ──

    [Fact]
    public void SecureState_AllPassOrInfo()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void InsecureState_MultipleCriticalAndWarnings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.True(result.Findings.Count(f => f.Severity == Severity.Critical) >= 2, "Expected at least 2 critical findings");
        Assert.True(result.Findings.Count(f => f.Severity == Severity.Warning) >= 4, "Expected at least 4 warning findings");
    }

    [Fact]
    public void InsecureState_HasRemediationGuidance()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var warnings = result.Findings.Where(f => f.Severity == Severity.Warning || f.Severity == Severity.Critical);
        foreach (var finding in warnings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Finding '{finding.Title}' should have remediation guidance");
        }
    }

    [Fact]
    public void AllFindingsHaveCategory()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        foreach (var finding in result.Findings)
        {
            Assert.Equal("Bluetooth", finding.Category);
        }
    }

    [Fact]
    public void AllFindingsHaveTitle()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title));
        }
    }

    [Fact]
    public void AllFindingsHaveDescription()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Description));
        }
    }

    // ── Edge cases ──

    [Fact]
    public void MultipleUnauthenticatedDevices_CountInTitle()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Dev1", Authenticated = false, DeviceType = "Audio" },
            new() { Name = "Dev2", Authenticated = false, DeviceType = "Peripheral" },
            new() { Name = "Dev3", Authenticated = false, DeviceType = "Phone" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "3 Unauthenticated Paired Device(s)");
    }

    [Fact]
    public void MultipleStaleDevices_CountInTitle()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Old1", Authenticated = true, DeviceType = "Audio", DaysSinceLastUse = 100 },
            new() { Name = "Old2", Authenticated = true, DeviceType = "Audio", DaysSinceLastUse = 200 },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "2 Stale Paired Device(s)");
    }

    [Fact]
    public void DeviceAt90Days_NotStale()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "Borderline", Authenticated = true, DeviceType = "Audio", DaysSinceLastUse = 90 },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Stale"));
    }

    [Fact]
    public void DeviceAt91Days_IsStale()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "JustStale", Authenticated = true, DeviceType = "Audio", DaysSinceLastUse = 91 },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Stale"));
    }

    [Fact]
    public void DriverAt365Days_NotOutdated()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 365;
        state.DriverVersion = "21.0.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title == "Bluetooth Driver Outdated");
        Assert.DoesNotContain(result.Findings, f => f.Title == "Bluetooth Driver Aging");
    }

    [Fact]
    public void DriverAt366Days_IsAging()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 366;
        state.DriverVersion = "21.0.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Aging");
    }

    [Fact]
    public void DriverAt730Days_StillAging()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 730;
        state.DriverVersion = "19.0.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Aging");
        Assert.DoesNotContain(result.Findings, f => f.Title == "Bluetooth Driver Outdated");
    }

    [Fact]
    public void DriverAt731Days_IsOutdated()
    {
        var state = MakeSecureState();
        state.DriverAgeDays = 731;
        state.DriverVersion = "19.0.0.1";
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title == "Bluetooth Driver Outdated");
    }

    [Fact]
    public void NoPairedDevicesRadioOff_NoPairedDeviceFinding()
    {
        var state = MakeSecureState();
        state.RadioEnabled = false;
        state.PairedDevices = new List<PairedDevice>();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title == "No Paired Devices");
    }

    [Fact]
    public void RiskyServicesKnownList_AllRecognized()
    {
        Assert.True(BluetoothAudit.RiskyServices.Count >= 7);
        Assert.Contains("OBEX Object Push", BluetoothAudit.RiskyServices.Keys);
        Assert.Contains("Serial Port", BluetoothAudit.RiskyServices.Keys);
        Assert.Contains("Personal Area Network", BluetoothAudit.RiskyServices.Keys);
    }

    [Fact]
    public void SuspiciousDeviceTypes_ContainsExpected()
    {
        Assert.Contains("Uncategorized", BluetoothAudit.SuspiciousDeviceTypes);
        Assert.Contains("Network", BluetoothAudit.SuspiciousDeviceTypes);
    }

    [Fact]
    public void RadioEnabled_HasFixCommand()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title == "Bluetooth Radio Enabled");
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void ServiceRunningWithoutRadio_HasFixCommand()
    {
        var state = MakeSecureState();
        state.RadioEnabled = false;
        state.BluetoothServiceState = ServiceRunState.Running;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title == "Bluetooth Service Running Without Radio");
        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
    }

    [Fact]
    public void SspNull_NoSspFindings()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.SspSupported = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Simple Pairing"));
    }

    [Fact]
    public void EncryptionNull_NoEncryptionFindings()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.EncryptionEnforced = null;
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Encryption"));
    }

    [Fact]
    public void UnauthenticatedDeviceUsesAddressWhenNoName()
    {
        var state = MakeSecureState();
        state.RadioEnabled = true;
        state.PairedDevices = new List<PairedDevice>
        {
            new() { Name = "", Address = "AA:BB:CC:DD:EE:FF", Authenticated = false, DeviceType = "Audio" },
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Unauthenticated"));
        Assert.Contains("AA:BB:CC:DD:EE:FF", finding.Description);
    }
}
