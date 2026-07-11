using WinSentinel.Core.Audits;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="EncryptionAnalyzer"/> - the pure, I/O-free encryption
/// posture decision logic behind the <see cref="EncryptionAudit"/> module. Previously
/// these parsers and thresholds lived inline inside the manage-bde / Get-Tpm / registry
/// / X509-store collection methods and could only be exercised by integration tests
/// that asserted "a finding exists", never the actual classification.
///
/// These tests pin every security-relevant boundary directly with synthetic input:
/// BitLocker status parsing + the system-drive-Critical rule, TPM parsing + the
/// present/ready/enabled matrix + TPM 1.2 outdated detection, SChannel protocol
/// enable/disable rules, weak cipher-suite detection, certificate weakness
/// classification (expiry / weak key / weak signature), Credential Guard
/// running/configured/off, and DPAPI master-key protection. All deterministic -
/// no shell, no registry, no certificate store, no clock.
/// </summary>
public class EncryptionAnalyzerTests
{
    private const string Cat = "Encryption";
    private const string Schannel = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    // ----------------------------------------------------------------------
    // BitLocker: ParseBitLockerStatus
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("'manage-bde' is not recognized as an internal or external command")]
    [InlineData("The system cannot find the file specified - not found")]
    public void ParseBitLocker_Unavailable(string? output)
    {
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Unavailable, s.Status);
    }

    [Fact]
    public void ParseBitLocker_FullyEncryptedProtected_Encrypted()
    {
        var output = @"
Volume C: [OSDisk]
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 256
    Protection Status:    Protection On
    Key Protectors:
        TPM
        Numerical Password";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Encrypted, s.Status);
        Assert.Equal("XTS-AES 256", s.EncryptionMethod);
        Assert.Contains("TPM", s.KeyProtectors);
        Assert.Contains("Numerical Password", s.KeyProtectors);
    }

    [Fact]
    public void ParseBitLocker_InProgress_Partial()
    {
        var output = @"
    Conversion Status:    Encryption in Progress
    Percentage Encrypted: 42.0%
    Encryption Method:    AES-CBC 128
    Protection Status:    Protection On";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Partial, s.Status);
        Assert.Equal("AES-CBC 128", s.EncryptionMethod);
    }

    [Fact]
    public void ParseBitLocker_FullyDecrypted_NotEncrypted()
    {
        var output = @"
    Conversion Status:    Fully Decrypted
    Percentage Encrypted: 0.0%
    Protection Status:    Protection Off";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.NotEncrypted, s.Status);
    }

    [Fact]
    public void ParseBitLocker_PowerShellEncryptionPercentage100_Encrypted()
    {
        // Get-BitLockerVolume Format-List style: "ProtectionStatus      : On"
        var output = "VolumeStatus          : FullyEncrypted\nEncryptionPercentage  : 100\nProtectionStatus      : On\nEncryptionMethod      : XtsAes256";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Encrypted, s.Status);
    }

    [Fact]
    public void ParseBitLocker_NoMethodMatch_StaysUnknownMethod()
    {
        var output = "Conversion Status: Fully Encrypted\nPercentage Encrypted: 100\nProtection Status: Protection On";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal("Unknown", s.EncryptionMethod);
        Assert.Empty(s.KeyProtectors);
    }

    [Fact]
    public void ParseBitLocker_PrefersStrongestMethod_WhenMultiplePresent()
    {
        // Output mentions both AES 256 and the stronger XTS-AES 256: strongest wins.
        var output = "Encryption Method: XTS-AES 256 (was AES 256 previously)\nPercentage Encrypted: 100\nProtection On";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal("XTS-AES 256", s.EncryptionMethod);
    }

    // Regression: real `manage-bde -status` prints a single space after the colon
    // ("Percentage Encrypted: 100.0%") and the conversion status can read "Encrypted"
    // rather than "Fully Encrypted". The old spacing-brittle literals
    // ("percentage encrypted:    100") never matched that, so a fully-encrypted,
    // protected OS volume fell through to Partial ("encryption in progress").
    [Fact]
    public void ParseBitLocker_ManageBde100SingleSpace_NoFullyWord_Encrypted()
    {
        var output = @"
Volume C: [OSDisk]
    Conversion Status:    Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 256
    Protection Status:    Protection On
    Key Protectors:
        TPM";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Encrypted, s.Status);
    }

    // Regression: the old isNotEncrypted check did
    // (Contains("encryptionpercentage") && Contains(": 0")), and the ": 0" matched any
    // unrelated field (here WipePercentage : 0). A 45%-encrypting protected volume was
    // therefore mis-reported NotEncrypted (Critical) instead of Partial.
    [Fact]
    public void ParseBitLocker_PartialWithUnrelatedZeroField_StaysPartial()
    {
        var output = "VolumeStatus          : EncryptionInProgress\n" +
                     "EncryptionPercentage  : 45\n" +
                     "WipePercentage        : 0\n" +
                     "ProtectionStatus      : On\n" +
                     "EncryptionMethod      : XtsAes256";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Partial, s.Status);
    }

    // Regression: a fully-encrypted volume with an unrelated ": 0" field must stay
    // Encrypted (not be dragged toward NotEncrypted by the old substring collision).
    [Fact]
    public void ParseBitLocker_FullyEncryptedWithUnrelatedZeroField_Encrypted()
    {
        var output = "VolumeStatus          : FullyEncrypted\n" +
                     "EncryptionPercentage  : 100\n" +
                     "WipePercentage        : 0\n" +
                     "ProtectionStatus      : On\n" +
                     "EncryptionMethod      : XtsAes256";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Encrypted, s.Status);
    }

    // The numeric parse reads the FIRST token of the percentage field's value, so a
    // mid-conversion drive at a non-round percentage is correctly Partial.
    [Fact]
    public void ParseBitLocker_ManageBde72Percent_Partial()
    {
        var output = @"
    Conversion Status:    Encryption in Progress
    Percentage Encrypted: 72.4%
    Protection Status:    Protection On";
        var s = EncryptionAnalyzer.ParseBitLockerStatus(output);
        Assert.Equal(EncryptionAnalyzer.BitLockerStatus.Partial, s.Status);
    }

    [Theory]
    [InlineData("100.0%", true, 100)]
    [InlineData("100", true, 100)]
    [InlineData("0.0%", true, 0)]
    [InlineData("45", true, 45)]
    [InlineData(" 72.4% ", true, 72.4)]
    [InlineData("On", false, 0)]
    [InlineData("", false, 0)]
    [InlineData(null, false, 0)]
    public void TryParseLeadingPercent_ParsesLeadingNumberOnly(string? value, bool ok, double expected)
    {
        var got = EncryptionAnalyzer.TryParseLeadingPercent(value, out var p);
        Assert.Equal(ok, got);
        if (ok) Assert.Equal(expected, p, 3);
    }

    // ----------------------------------------------------------------------
    // BitLocker: IsSystemDrive + BuildBitLockerFinding severity
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData("C:", true)]
    [InlineData("c:", true)]
    [InlineData(" C:", true)]
    [InlineData("D:", false)]
    [InlineData("E:", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    public void IsSystemDrive_Works(string? drive, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsSystemDrive(drive));
    }

    [Fact]
    public void BuildBitLocker_SystemDriveNotEncrypted_IsCritical()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState { Status = EncryptionAnalyzer.BitLockerStatus.NotEncrypted };
        var f = EncryptionAnalyzer.BuildBitLockerFinding("C:", state);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal(Cat, f.Category);
        Assert.Contains("Not Encrypted", f.Title);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void BuildBitLocker_DataDriveNotEncrypted_IsWarning()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState { Status = EncryptionAnalyzer.BitLockerStatus.NotEncrypted };
        var f = EncryptionAnalyzer.BuildBitLockerFinding("D:", state);
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void BuildBitLocker_Encrypted_IsPass_WithMethodAndProtectors()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState
        {
            Status = EncryptionAnalyzer.BitLockerStatus.Encrypted,
            EncryptionMethod = "XTS-AES 256",
            KeyProtectors = new List<string> { "TPM", "Numerical Password" }
        };
        var f = EncryptionAnalyzer.BuildBitLockerFinding("C:", state);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("XTS-AES 256", f.Description);
        Assert.Contains("TPM, Numerical Password", f.Description);
    }

    [Theory]
    [InlineData("XTS-AES 256", false)]
    [InlineData("xts-aes 256", false)]   // case-insensitive
    [InlineData("XTS-AES 128", true)]
    [InlineData("AES-CBC 256", true)]
    [InlineData("AES-CBC 128", true)]
    [InlineData("AES 256", true)]
    [InlineData("AES 128", true)]
    [InlineData("Unknown", false)]       // unrecognized → do not downgrade
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsWeakBitLockerMethod_ClassifiesBelowXtsAes256(string? method, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsWeakBitLockerMethod(method));
    }

    [Fact]
    public void BuildBitLocker_EncryptedWithWeakMethod_IsWarning()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState
        {
            Status = EncryptionAnalyzer.BitLockerStatus.Encrypted,
            EncryptionMethod = "AES-CBC 128",
            KeyProtectors = new List<string> { "TPM" }
        };
        var f = EncryptionAnalyzer.BuildBitLockerFinding("C:", state);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Equal(Cat, f.Category);
        Assert.Contains("Weak Encryption Method", f.Title);
        Assert.Contains("AES-CBC 128", f.Description);
        Assert.Contains("XTS-AES 256", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void BuildBitLocker_EncryptedWithUnknownMethod_StillPasses()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState
        {
            Status = EncryptionAnalyzer.BitLockerStatus.Encrypted,
            EncryptionMethod = "Unknown",
            KeyProtectors = new List<string> { "TPM" }
        };
        var f = EncryptionAnalyzer.BuildBitLockerFinding("C:", state);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildBitLocker_Partial_IsWarning()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState { Status = EncryptionAnalyzer.BitLockerStatus.Partial };
        Assert.Equal(Severity.Warning, EncryptionAnalyzer.BuildBitLockerFinding("C:", state).Severity);
    }

    [Fact]
    public void BuildBitLocker_Unavailable_IsInfo()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState { Status = EncryptionAnalyzer.BitLockerStatus.Unavailable };
        Assert.Equal(Severity.Info, EncryptionAnalyzer.BuildBitLockerFinding("C:", state).Severity);
    }

    [Fact]
    public void BuildBitLocker_NoProtectors_SaysNoneDetected()
    {
        var state = new EncryptionAnalyzer.BitLockerDriveState { Status = EncryptionAnalyzer.BitLockerStatus.Encrypted };
        Assert.Contains("None detected", EncryptionAnalyzer.BuildBitLockerFinding("C:", state).Description);
    }

    // ----------------------------------------------------------------------
    // TPM: ParseTpmPowerShell + BuildTpmPowerShellFinding
    // ----------------------------------------------------------------------

    private const string TpmReadyOutput = @"
TpmPresent                      : True
TpmReady                        : True
TpmEnabled                      : True
ManufacturerVersionFull20       : 7.2.2.0";

    [Fact]
    public void ParseTpm_PresentReadyEnabled()
    {
        var s = EncryptionAnalyzer.ParseTpmPowerShell(TpmReadyOutput);
        Assert.True(s.IsPresent);
        Assert.True(s.IsReady);
        Assert.True(s.IsEnabled);
        // ManufacturerVersionFull20 is the firmware revision, and its presence is a
        // TPM 2.0-only signal -> spec Version is inferred as 2.0, firmware kept separate.
        Assert.Equal("2.0", s.Version);
        Assert.Equal("7.2.2.0", s.FirmwareVersion);
    }

    [Fact]
    public void ParseTpm_Null_NotPresent()
    {
        var s = EncryptionAnalyzer.ParseTpmPowerShell(null);
        Assert.False(s.IsPresent);
        Assert.False(s.IsReady);
    }

    [Fact]
    public void ParseTpm_EnabledFalse_Detected()
    {
        var output = "TpmPresent                      : True\nTpmReady                        : False\nTpmEnabled                      : False";
        var s = EncryptionAnalyzer.ParseTpmPowerShell(output);
        Assert.True(s.IsPresent);
        Assert.False(s.IsEnabled);
        Assert.False(s.IsReady);
    }

    [Fact]
    public void ParseTpm_NotPresent_OtherFieldTrue_NotMisdetected()
    {
        // Regression: ParseTpmPowerShell matched a bare ": True" anywhere in the whole
        // Get-Tpm output, so a machine with NO TPM (TpmPresent : False) but ANY other
        // field reading ": True" (here RestartPending) was misdetected as present ->
        // "TPM Present but Disabled" instead of "TPM Not Available". Each field must be
        // read by its own name on its own line.
        var output =
            "TpmPresent                      : False\n" +
            "TpmReady                        : False\n" +
            "TpmEnabled                      : False\n" +
            "TpmActivated                    : False\n" +
            "RestartPending                  : True\n" +
            "LockedOut                       : False";
        var s = EncryptionAnalyzer.ParseTpmPowerShell(output);
        Assert.False(s.IsPresent);
        Assert.False(s.IsReady);
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal("TPM Not Available", f.Title);
    }

    [Fact]
    public void ParseTpm_ReadyFalse_OtherFieldTrue_NotMisreadAsReady()
    {
        // The old IsReady check keyed on the exact-spacing literal
        // "TpmReady                        : True"; with the field-name parse it now
        // reads TpmReady's own value, so an unrelated ": True" never flips IsReady.
        var output =
            "TpmPresent                      : True\n" +
            "TpmReady                        : False\n" +
            "TpmEnabled                      : True";
        var s = EncryptionAnalyzer.ParseTpmPowerShell(output);
        Assert.True(s.IsPresent);
        Assert.True(s.IsEnabled);
        Assert.False(s.IsReady);
    }

    [Fact]
    public void ParseTpm_TolerantOfColumnSpacing()
    {
        // Field values are read after the field-name + colon regardless of the
        // (variable) column padding Get-Tpm uses, not via a hardcoded-width literal.
        var output = "TpmPresent : True\nTpmReady: True\nTpmEnabled   :   True";
        var s = EncryptionAnalyzer.ParseTpmPowerShell(output);
        Assert.True(s.IsPresent);
        Assert.True(s.IsReady);
        Assert.True(s.IsEnabled);
    }

    [Fact]
    public void BuildTpm_PresentReadyEnabled_IsPass()
    {
        var s = EncryptionAnalyzer.ParseTpmPowerShell(TpmReadyOutput);
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
        // Firmware revision (not a bogus "spec version") is surfaced to the user.
        Assert.Contains("7.2.2.0", f.Description);
    }

    [Fact]
    public void BuildTpm_Tpm12Present_IsOutdatedWarning_NotPass()
    {
        // Regression: a present-and-ready TPM that reports the 1.2 spec generation
        // must be flagged as outdated, NOT reported as a healthy pass. Previously the
        // PowerShell path never consulted the spec version at all, so a real TPM 1.2
        // silently passed.
        var s = new EncryptionAnalyzer.TpmState
        {
            IsPresent = true,
            IsReady = true,
            IsEnabled = true,
            Version = "1.2",
            FirmwareVersion = "3.1.0.0"
        };
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("1.2", f.Title);
        Assert.Contains("Outdated", f.Title);
    }

    [Fact]
    public void BuildTpm_Tpm20Firmware_StartingWith12_StillPasses()
    {
        // Guard against the false-positive: a genuine TPM 2.0 whose *firmware* string
        // happens to start with "1.2" must NOT be misread as an outdated 1.2 module,
        // because the spec Version ("2.0") is what drives the decision.
        var s = new EncryptionAnalyzer.TpmState
        {
            IsPresent = true,
            IsReady = true,
            IsEnabled = true,
            Version = "2.0",
            FirmwareVersion = "1.2.99.0"
        };
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildTpm_PresentDisabled_IsWarning()
    {
        var s = new EncryptionAnalyzer.TpmState { IsPresent = true, IsEnabled = false, IsReady = false };
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Disabled", f.Title);
    }

    [Fact]
    public void BuildTpm_PresentNotReady_IsWarning()
    {
        var s = new EncryptionAnalyzer.TpmState { IsPresent = true, IsEnabled = true, IsReady = false };
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Not Ready", f.Title);
    }

    [Fact]
    public void BuildTpm_NotPresent_IsWarning()
    {
        var s = new EncryptionAnalyzer.TpmState { IsPresent = false };
        var f = EncryptionAnalyzer.BuildTpmPowerShellFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Not Available", f.Title);
    }

    [Theory]
    [InlineData("1.2", true)]
    [InlineData("1.2.0.0", true)]
    [InlineData("2.0", false)]
    [InlineData("7.2.2.0", false)]
    [InlineData("Unknown", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    // WMI Win32_Tpm.SpecVersion is a comma-delimited list: only the leading family
    // token decides, so revision fields starting with "1.2" must not false-positive.
    [InlineData("1.2, 2, 3", true)]
    [InlineData("2.0, 0, 1.59", false)]
    [InlineData("2.0, 0, 1.2", false)]
    [InlineData("  1.2 , 2 , 3 ", true)]
    public void IsOutdatedTpmVersion_Works(string? version, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsOutdatedTpmVersion(version));
    }

    // ----------------------------------------------------------------------
    // TLS / SChannel protocol rules
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(0, -1, false)]   // explicitly disabled wins
    [InlineData(0, 0, false)]
    [InlineData(1, -1, true)]    // explicitly enabled wins
    [InlineData(1, 1, true)]     // explicit Enabled beats DisabledByDefault
    [InlineData(-1, 1, false)]   // not present + disabled-by-default
    [InlineData(-1, -1, false)]  // not configured -> treated as not enabled
    [InlineData(-1, 0, false)]
    public void IsProtocolEnabled_Matrix(int enabled, int disabledByDefault, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsProtocolEnabled(enabled, disabledByDefault));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(-1, false)]
    public void IsProtocolExplicitlyDisabled_Works(int enabled, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsProtocolExplicitlyDisabled(enabled));
    }

    [Fact]
    public void BuildLegacy_BothDisabled_IsPass()
    {
        var f = EncryptionAnalyzer.BuildLegacyProtocolFinding("TLS 1.0", false, false, Schannel);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildLegacy_Tls10Enabled_IsWarning()
    {
        var f = EncryptionAnalyzer.BuildLegacyProtocolFinding("TLS 1.0", true, false, Schannel);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("client", f.Description);
    }

    [Fact]
    public void BuildLegacy_Ssl30Enabled_IsCritical()
    {
        var f = EncryptionAnalyzer.BuildLegacyProtocolFinding("SSL 3.0", true, true, Schannel);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("client and server", f.Description);
    }

    [Fact]
    public void BuildLegacy_ServerOnly_MentionsServer()
    {
        var f = EncryptionAnalyzer.BuildLegacyProtocolFinding("TLS 1.1", false, true, Schannel);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("server", f.Description);
    }

    [Fact]
    public void BuildModern_Enabled_IsPass()
    {
        var f = EncryptionAnalyzer.BuildModernProtocolFinding("TLS 1.2", false, false, Schannel);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildModern_Tls12Disabled_IsCritical()
    {
        var f = EncryptionAnalyzer.BuildModernProtocolFinding("TLS 1.2", true, false, Schannel);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Disabled", f.Title);
    }

    [Fact]
    public void BuildModern_Tls13Disabled_IsCritical()
    {
        var f = EncryptionAnalyzer.BuildModernProtocolFinding("TLS 1.3", true, true, Schannel);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("client and server", f.Description);
    }

    // ----------------------------------------------------------------------
    // Cipher suites
    // ----------------------------------------------------------------------

    [Fact]
    public void FindWeakCipherSuites_Null_Empty()
    {
        Assert.Empty(EncryptionAnalyzer.FindWeakCipherSuites(null));
        Assert.Empty(EncryptionAnalyzer.FindWeakCipherSuites(""));
    }

    [Fact]
    public void FindWeakCipherSuites_DetectsEachToken()
    {
        var fns = "TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_DES_CBC_SHA,TLS_RSA_WITH_NULL_MD5,TLS_AES_256_GCM_SHA384";
        var weak = EncryptionAnalyzer.FindWeakCipherSuites(fns);
        Assert.Equal(3, weak.Count); // RC4, DES, NULL/MD5
        Assert.Contains(weak, w => w.Contains("RC4"));
        Assert.Contains(weak, w => w.Contains("DES"));
        Assert.DoesNotContain(weak, w => w.Contains("AES_256_GCM"));
    }

    [Fact]
    public void FindWeakCipherSuites_AllStrong_Empty()
    {
        var fns = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256";
        Assert.Empty(EncryptionAnalyzer.FindWeakCipherSuites(fns));
    }

    [Fact]
    public void BuildCipherSuite_Null_IsInfoSystemDefault()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding(null);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("System Default", f.Title);
    }

    [Fact]
    public void BuildCipherSuite_Weak_IsWarning()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_WITH_RC4_128_SHA,TLS_AES_256_GCM_SHA384");
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Weak Cipher Suites", f.Title);
    }

    // The weak-cipher warning must offer a fix that opens the Group Policy editor.
    [Fact]
    public void BuildCipherSuite_Weak_HasGroupPolicyFix()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_WITH_RC4_128_SHA,TLS_AES_256_GCM_SHA384");
        Assert.Equal(EncryptionAnalyzer.OpenGroupPolicyFix, f.FixCommand);
    }

    [Fact]
    public void BuildCipherSuite_AllStrong_IsPass()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256");
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("2 suite", f.Description);
    }

    // --- Severity tiering: critical (no protection) vs warning (weak-but-encrypted) ---

    [Fact]
    public void ClassifyWeakCipherSuites_Null_BothEmpty()
    {
        var (crit, warn) = EncryptionAnalyzer.ClassifyWeakCipherSuites(null);
        Assert.Empty(crit);
        Assert.Empty(warn);
        var (crit2, warn2) = EncryptionAnalyzer.ClassifyWeakCipherSuites("   ");
        Assert.Empty(crit2);
        Assert.Empty(warn2);
    }

    [Fact]
    public void ClassifyWeakCipherSuites_SplitsTiers_NoOverlap()
    {
        // NULL + EXPORT + anon + single-DES => critical; RC4 + 3DES + MD5 => warning; GCM strong.
        var fns = "TLS_RSA_WITH_NULL_SHA,"
                + "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,"
                + "TLS_DH_anon_WITH_AES_128_CBC_SHA,"
                + "TLS_RSA_WITH_DES_CBC_SHA,"
                + "TLS_RSA_WITH_RC4_128_SHA,"
                + "TLS_RSA_WITH_3DES_EDE_CBC_SHA,"
                + "TLS_AES_256_GCM_SHA384";
        var (crit, warn) = EncryptionAnalyzer.ClassifyWeakCipherSuites(fns);

        Assert.Contains(crit, s => s.Contains("NULL"));
        Assert.Contains(crit, s => s.Contains("EXPORT"));
        Assert.Contains(crit, s => s.Contains("anon"));
        Assert.Contains(crit, s => s.Contains("WITH_DES_"));   // single 56-bit DES
        Assert.Contains(warn, s => s.Contains("RC4"));
        Assert.Contains(warn, s => s.Contains("3DES"));

        // No suite appears in both buckets.
        Assert.Empty(crit.Intersect(warn));
        // Strong GCM suite is in neither.
        Assert.DoesNotContain(crit.Concat(warn), s => s.Contains("AES_256_GCM"));
    }

    [Fact]
    public void ClassifyWeakCipherSuites_TripleDes_IsWarningNotCritical()
    {
        // Sweet32 (CVE-2016-2183): 3DES is weak-but-encrypting, so it must land in Warning,
        // NOT be misclassified as single-DES Critical. The "_DES_" critical token has
        // underscores precisely so it does not match "3DES".
        var (crit, warn) = EncryptionAnalyzer.ClassifyWeakCipherSuites("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        Assert.Empty(crit);
        Assert.Single(warn);
        Assert.Contains("3DES", warn[0]);
    }

    [Fact]
    public void ClassifyWeakCipherSuites_CriticalWins_WhenSuiteHasBothTokens()
    {
        // A single suite that is both EXPORT (critical) and MD5 (warning) is counted once, in
        // the critical tier only.
        var (crit, warn) = EncryptionAnalyzer.ClassifyWeakCipherSuites("TLS_RSA_EXPORT_WITH_RC4_40_MD5");
        Assert.Single(crit);
        Assert.Empty(warn);
    }

    [Fact]
    public void BuildCipherSuite_NullCipher_IsCritical()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_WITH_NULL_SHA,TLS_AES_256_GCM_SHA384");
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Insecure Cipher Suites", f.Title);
        Assert.Equal(EncryptionAnalyzer.OpenGroupPolicyFix, f.FixCommand);
    }

    [Fact]
    public void BuildCipherSuite_ExportCipher_IsCritical()
    {
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA");
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void BuildCipherSuite_TripleDesOnly_IsWarning()
    {
        // 3DES alone must be a Warning, and the message should name Sweet32/3DES, not DES.
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_AES_128_GCM_SHA256");
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Weak Cipher Suites", f.Title);
        Assert.Contains("3DES", f.Description);
    }

    [Fact]
    public void BuildCipherSuite_CriticalFinding_CountsBothTiers()
    {
        // One NULL (critical) + one RC4 (warning) => Critical finding whose count is 2.
        var f = EncryptionAnalyzer.BuildCipherSuiteFinding("TLS_RSA_WITH_NULL_MD5,TLS_RSA_WITH_RC4_128_SHA");
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("(2)", f.Title);
    }

    // ----------------------------------------------------------------------
    // Certificates: weak key / weak signature predicates
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData(true, 1024, true)]
    [InlineData(true, 2047, true)]
    [InlineData(true, 2048, false)]
    [InlineData(true, 4096, false)]
    [InlineData(false, 1024, false)] // non-RSA never weak-by-size here
    [InlineData(true, 0, false)]     // unknown size -> not flagged
    public void IsWeakRsaKey_Works(bool isRsa, int bits, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsWeakRsaKey(isRsa, bits));
    }

    [Theory]
    [InlineData("sha1RSA", true)]
    [InlineData("SHA1withRSA", true)]
    [InlineData("md5RSA", true)]
    [InlineData("md2RSA", true)]
    [InlineData("sha256RSA", false)]
    [InlineData("sha384ECDSA", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsWeakSignature_Works(string? alg, bool expected)
    {
        Assert.Equal(expected, EncryptionAnalyzer.IsWeakSignature(alg));
    }

    // ----------------------------------------------------------------------
    // Certificates: ClassifyCertificates + BuildCertificateFindings
    // ----------------------------------------------------------------------

    private static readonly DateTime Now = new(2026, 6, 11, 0, 0, 0, DateTimeKind.Utc);

    private static EncryptionAnalyzer.CertFact Cert(
        DateTime notAfter, bool isRsa = true, int bits = 4096, string sig = "sha256RSA", string name = "cert")
        => new() { DisplayName = name, NotAfter = notAfter, IsRsa = isRsa, RsaKeyBits = bits, SignatureAlgorithm = sig };

    [Fact]
    public void ClassifyCerts_Null_EmptySummary()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(null, Now);
        Assert.Equal(0, s.Total);
        Assert.True(s.IsClean);
    }

    [Fact]
    public void ClassifyCerts_HealthyCert_IsClean()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddYears(1)) }, Now);
        Assert.Equal(1, s.Total);
        Assert.True(s.IsClean);
        Assert.Equal(0, s.Expired);
    }

    [Fact]
    public void ClassifyCerts_Expired_Counted()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddDays(-1)) }, Now);
        Assert.Equal(1, s.Expired);
        Assert.False(s.IsClean);
        Assert.Contains(s.Issues, i => i.StartsWith("EXPIRED"));
    }

    [Fact]
    public void ClassifyCerts_ExpiringSoon_Counted()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddDays(10)) }, Now);
        Assert.Equal(1, s.ExpiringSoon);
        Assert.Equal(0, s.Expired);
    }

    [Fact]
    public void ClassifyCerts_ExpiryBoundary_30DaysIsSoon_31IsNot()
    {
        var soon = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddDays(20)) }, Now);
        Assert.Equal(1, soon.ExpiringSoon);
        var ok = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddDays(40)) }, Now);
        Assert.Equal(0, ok.ExpiringSoon);
        Assert.True(ok.IsClean);
    }

    [Fact]
    public void ClassifyCerts_WeakKey_Counted()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddYears(1), bits: 1024) }, Now);
        Assert.Equal(1, s.WeakKey);
    }

    [Fact]
    public void ClassifyCerts_WeakSignature_Counted()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddYears(1), sig: "sha1RSA") }, Now);
        Assert.Equal(1, s.WeakSignature);
    }

    [Fact]
    public void ClassifyCerts_MultipleIssuesOnOneCert_AllCounted()
    {
        // Expired AND weak key AND weak signature.
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddDays(-5), bits: 1024, sig: "md5RSA") }, Now);
        Assert.Equal(1, s.Expired);
        Assert.Equal(1, s.WeakKey);
        Assert.Equal(1, s.WeakSignature);
        Assert.False(s.IsClean);
    }

    [Fact]
    public void BuildCertFindings_Clean_SinglePass()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddYears(2)) }, Now);
        var findings = EncryptionAnalyzer.BuildCertificateFindings(s);
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
    }

    [Fact]
    public void BuildCertFindings_AllProblems_FourWarningsNoPass()
    {
        var certs = new[]
        {
            Cert(Now.AddDays(-1), name: "expired"),
            Cert(Now.AddDays(5), name: "soon"),
            Cert(Now.AddYears(1), bits: 1024, name: "weakkey"),
            Cert(Now.AddYears(1), sig: "sha1RSA", name: "weaksig"),
        };
        var s = EncryptionAnalyzer.ClassifyCertificates(certs, Now);
        var findings = EncryptionAnalyzer.BuildCertificateFindings(s);
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.Warning, f.Severity));
        Assert.DoesNotContain(findings, f => f.Severity == Severity.Pass);
    }

    // Every certificate-store warning must carry an actionable fix that opens the
    // certificate manager so the user can remove/renew (auto-deleting certs is unsafe).
    [Fact]
    public void BuildCertFindings_EveryWarning_HasCertManagerFix()
    {
        var certs = new[]
        {
            Cert(Now.AddDays(-1), name: "expired"),
            Cert(Now.AddDays(5), name: "soon"),
            Cert(Now.AddYears(1), bits: 1024, name: "weakkey"),
            Cert(Now.AddYears(1), sig: "sha1RSA", name: "weaksig"),
        };
        var s = EncryptionAnalyzer.ClassifyCertificates(certs, Now);
        var findings = EncryptionAnalyzer.BuildCertificateFindings(s);
        Assert.Equal(4, findings.Count);
        Assert.All(findings, f =>
            Assert.Equal(EncryptionAnalyzer.OpenCertManagerFix, f.FixCommand));
    }

    // A clean store's single Pass must NOT advertise a fix command (nothing to fix).
    [Fact]
    public void BuildCertFindings_CleanPass_HasNoFix()
    {
        var s = EncryptionAnalyzer.ClassifyCertificates(new[] { Cert(Now.AddYears(2)) }, Now);
        var findings = EncryptionAnalyzer.BuildCertificateFindings(s);
        Assert.Single(findings);
        Assert.True(string.IsNullOrEmpty(findings[0].FixCommand));
    }

    // ----------------------------------------------------------------------
    // Trusted root store
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildTrustedRoot_NoUserRoots_IsPass()
    {
        var f = EncryptionAnalyzer.BuildTrustedRootFinding(0, 0, null);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildTrustedRoot_FewSelfSigned_IsInfo()
    {
        var f = EncryptionAnalyzer.BuildTrustedRootFinding(2, 2, new[] { "Fiddler Root", "mitmproxy" });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Fiddler Root", f.Description);
    }

    [Fact]
    public void BuildTrustedRoot_ManySelfSigned_IsWarning()
    {
        // SuspiciousRootThreshold is 3 -> 4 self-signed escalates to Warning.
        var names = new[] { "a", "b", "c", "d" };
        var f = EncryptionAnalyzer.BuildTrustedRootFinding(4, 4, names);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Suspicious", f.Title);
    }

    // The suspicious-root warning must offer the certificate-manager fix; the
    // benign Info/Pass variants must not (nothing actionable).
    [Fact]
    public void BuildTrustedRoot_SuspiciousWarning_HasCertManagerFix()
    {
        var f = EncryptionAnalyzer.BuildTrustedRootFinding(4, 4, new[] { "a", "b", "c", "d" });
        Assert.Equal(EncryptionAnalyzer.OpenCertManagerFix, f.FixCommand);
    }

    [Fact]
    public void BuildTrustedRoot_InfoAndPass_HaveNoFix()
    {
        var info = EncryptionAnalyzer.BuildTrustedRootFinding(2, 2, new[] { "Fiddler Root", "mitmproxy" });
        var pass = EncryptionAnalyzer.BuildTrustedRootFinding(0, 0, null);
        Assert.True(string.IsNullOrEmpty(info.FixCommand));
        Assert.True(string.IsNullOrEmpty(pass.FixCommand));
    }

    // ----------------------------------------------------------------------
    // Fix-command safety: every encryption fix payload must actually be
    // executable by FixEngine, i.e. it must pass InputSanitizer.CheckDangerousCommand
    // (which blocks pipes, semicolons, sub-expressions, Start-Process shell launches,
    // etc.). A fix that is silently blocked is worse than no fix at all - the WPF /
    // CLI Fix button would appear available but always fail. These bare MMC snap-in
    // names are the safe form; this pins that they stay safe.
    // ----------------------------------------------------------------------

    [Theory]
    [InlineData("certmgr.msc")]
    [InlineData("gpedit.msc")]
    public void EncryptionFixCommands_AreNotBlockedBySafetyCheck(string fixCommand)
    {
        Assert.Null(InputSanitizer.CheckDangerousCommand(fixCommand));
    }

    [Fact]
    public void EncryptionFixConstants_MatchExpectedSnapIns()
    {
        Assert.Equal("certmgr.msc", EncryptionAnalyzer.OpenCertManagerFix);
        Assert.Equal("gpedit.msc", EncryptionAnalyzer.OpenGroupPolicyFix);
        Assert.Null(InputSanitizer.CheckDangerousCommand(EncryptionAnalyzer.OpenCertManagerFix));
        Assert.Null(InputSanitizer.CheckDangerousCommand(EncryptionAnalyzer.OpenGroupPolicyFix));
    }

    [Fact]
    public void BuildTrustedRoot_ExactlyThreshold_StaysInfo()
    {
        var f = EncryptionAnalyzer.BuildTrustedRootFinding(3, 3, new[] { "a", "b", "c" });
        Assert.Equal(Severity.Info, f.Severity);
    }

    // ----------------------------------------------------------------------
    // Credential Guard
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildCredGuard_Running_IsPass()
    {
        var s = new EncryptionAnalyzer.CredentialGuardState { CredentialGuardRunning = true, VbsStatus = "Running" };
        Assert.Equal(Severity.Pass, EncryptionAnalyzer.BuildCredentialGuardFinding(s).Severity);
    }

    [Fact]
    public void BuildCredGuard_ConfiguredNotRunning_IsWarning()
    {
        var s = new EncryptionAnalyzer.CredentialGuardState { LsaCfgFlags = 1, CredentialGuardRunning = false };
        var f = EncryptionAnalyzer.BuildCredentialGuardFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Configured but Not Running", f.Title);
    }

    [Fact]
    public void BuildCredGuard_ConfiguredViaWmi_IsWarning()
    {
        var s = new EncryptionAnalyzer.CredentialGuardState { CredentialGuardConfigured = true };
        Assert.Equal(Severity.Warning, EncryptionAnalyzer.BuildCredentialGuardFinding(s).Severity);
    }

    [Fact]
    public void BuildCredGuard_Off_IsWarningNotEnabled()
    {
        var s = new EncryptionAnalyzer.CredentialGuardState { LsaCfgFlags = -1, DeviceGuardEnabled = -1 };
        var f = EncryptionAnalyzer.BuildCredentialGuardFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Not Enabled", f.Title);
    }

    [Fact]
    public void BuildCredGuard_RunningWins_EvenIfConfiguredFlagsSet()
    {
        var s = new EncryptionAnalyzer.CredentialGuardState { CredentialGuardRunning = true, LsaCfgFlags = 1 };
        Assert.Equal(Severity.Pass, EncryptionAnalyzer.BuildCredentialGuardFinding(s).Severity);
    }

    // ----------------------------------------------------------------------
    // DPAPI
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildDpapi_NoKeys_IsInfo()
    {
        var s = new EncryptionAnalyzer.DpapiState { MasterKeysExist = false };
        var f = EncryptionAnalyzer.BuildDpapiFinding(s);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Found", f.Title);
    }

    [Fact]
    public void BuildDpapi_KeysWithCredGuard_IsPass()
    {
        var s = new EncryptionAnalyzer.DpapiState { MasterKeysExist = true, KeyFileCount = 3, LsaCfgFlags = 1 };
        var f = EncryptionAnalyzer.BuildDpapiFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Credential Guard", f.Title);
    }

    [Fact]
    public void BuildDpapi_KeysDomainJoined_IsPass()
    {
        var s = new EncryptionAnalyzer.DpapiState { MasterKeysExist = true, KeyFileCount = 2, IsDomainJoined = true };
        var f = EncryptionAnalyzer.BuildDpapiFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Domain", f.Title);
    }

    [Fact]
    public void BuildDpapi_KeysStandalone_IsInfo()
    {
        var s = new EncryptionAnalyzer.DpapiState { MasterKeysExist = true, KeyFileCount = 1, IsDomainJoined = false, LsaCfgFlags = 0 };
        var f = EncryptionAnalyzer.BuildDpapiFinding(s);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("strong login password", f.Description);
    }

    [Fact]
    public void BuildDpapi_CredGuardBeatsDomain_WhenBoth()
    {
        var s = new EncryptionAnalyzer.DpapiState { MasterKeysExist = true, KeyFileCount = 2, IsDomainJoined = true, LsaCfgFlags = 1 };
        var f = EncryptionAnalyzer.BuildDpapiFinding(s);
        Assert.Contains("Credential Guard", f.Title);
    }

    // === Kernel DMA Protection ================================================

    [Fact]
    public void KernelDma_QueryFailed_IsInfoUnknown()
    {
        var s = EncryptionAnalyzer.ClassifyKernelDma(null, -1, querySucceeded: false);
        var f = EncryptionAnalyzer.BuildKernelDmaFinding(s);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Unknown", f.Title);
    }

    [Fact]
    public void KernelDma_NotAvailable_IsInfo()
    {
        // Query succeeded but property 6 absent => hardware/firmware unsupported.
        var s = EncryptionAnalyzer.ClassifyKernelDma(new[] { 1, 2, 3 }, -1, querySucceeded: true);
        Assert.False(s.IsAvailable);
        var f = EncryptionAnalyzer.BuildKernelDmaFinding(s);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Not Available", f.Title);
    }

    [Fact]
    public void KernelDma_Available_SecureDefault_Passes()
    {
        // Property 6 present, AllowDmaUnderLock absent (-1) => secure default.
        var s = EncryptionAnalyzer.ClassifyKernelDma(new[] { 1, EncryptionAnalyzer.DmaProtectionSecurityProperty }, -1, querySucceeded: true);
        Assert.True(s.IsAvailable);
        var f = EncryptionAnalyzer.BuildKernelDmaFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Enabled", f.Title);
    }

    [Fact]
    public void KernelDma_Available_ButAllowDmaUnderLock_Warns()
    {
        var s = EncryptionAnalyzer.ClassifyKernelDma(new[] { EncryptionAnalyzer.DmaProtectionSecurityProperty }, 1, querySucceeded: true);
        var f = EncryptionAnalyzer.BuildKernelDmaFinding(s);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("AllowDmaUnderLock", f.Description);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void KernelDma_AllowDmaUnderLockZero_IsSecure()
    {
        var s = EncryptionAnalyzer.ClassifyKernelDma(new[] { EncryptionAnalyzer.DmaProtectionSecurityProperty }, 0, querySucceeded: true);
        var f = EncryptionAnalyzer.BuildKernelDmaFinding(s);
        Assert.Equal(Severity.Pass, f.Severity);
    }
}
