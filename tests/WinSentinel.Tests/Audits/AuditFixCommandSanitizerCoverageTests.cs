using System.Collections.Generic;
using System.Linq;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Helpers;
using Xunit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Whole-module guard that EVERY <c>FixCommand</c> emitted by the aggregate
/// <c>Analyze(state)</c> entry points actually survives
/// <see cref="InputSanitizer.CheckDangerousCommand"/> — the exact safety check
/// <see cref="WinSentinel.Core.Services.FixEngine"/> runs on a fix string *before*
/// executing it.
///
/// Why this exists alongside <see cref="AuditFixCommandSanitizerTests"/>: that suite
/// pins a hand-picked list of historically-broken fix strings. It does NOT
/// systematically cover every command a module can emit, so a newly-added fix that
/// trips the sanitizer (a semicolon, a pipe-to-shell, <c>$(...)</c>, a backtick,
/// <c>&amp;&amp;</c>/<c>||</c>, a Run-key write, …) would ship as a "dead Fix button":
/// the WPF/CLI fix action looks available but ALWAYS fails with "Command blocked by
/// safety check" — strictly worse than emitting no fix at all. Five such dead buttons
/// had to be repaired in earlier releases.
///
/// This test drives the fix-command-bearing analyzers with worst-case synthetic
/// state that forces every remediation branch to fire, then asserts that none of the
/// resulting <c>FixCommand</c> strings are rejected by the sanitizer. The worst-case
/// state is also asserted to actually yield fix commands, so the guard can never
/// silently pass on an empty set.
///
/// Covered analyzers (i.e. the ones that actually emit <c>FixCommand</c> strings):
/// <see cref="NetworkPostureAnalyzer"/>, <see cref="PowerShellSecurityAnalyzer"/>,
/// <see cref="UsbAnalyzer"/>, <see cref="BluetoothAudit"/>, the certificate-store
/// findings of <see cref="EncryptionAnalyzer"/>, the ASR roll-up of
/// <see cref="AttackSurfaceReductionAnalyzer"/>, and the Controlled Folder Access
/// finding of <see cref="DefenderAnalyzer"/>. (Browser/EventLog/Identity and the
/// other Defender analyzers emit guidance-only findings with no executable fix, so
/// there is nothing to guard there.)
/// </summary>
public class AuditFixCommandSanitizerCoverageTests
{
    /// <summary>
    /// Assert that every non-empty FixCommand in <paramref name="findings"/> passes
    /// the sanitizer, and that at least <paramref name="minExpected"/> were present
    /// (so the worst-case state really exercised the remediation branches).
    /// </summary>
    private static void AssertAllFixCommandsSanitizerSafe(
        IEnumerable<WinSentinel.Core.Models.Finding> findings, int minExpected)
    {
        var withFixes = findings
            .Where(f => !string.IsNullOrWhiteSpace(f.FixCommand))
            .ToList();

        Assert.True(withFixes.Count >= minExpected,
            $"Expected at least {minExpected} fix commands from the worst-case state, " +
            $"but only {withFixes.Count} were produced — the test is no longer exercising " +
            "the remediation branches it was written to guard.");

        foreach (var finding in withFixes)
        {
            var reason = InputSanitizer.CheckDangerousCommand(finding.FixCommand);
            Assert.True(reason is null,
                $"FixCommand for '{finding.Title}' is rejected by the sanitizer and would be a " +
                $"dead Fix button: \"{finding.FixCommand}\" — blocked because: {reason}");
        }
    }

    [Fact]
    public void NetworkPostureAnalyzer_AllFixCommands_SurviveSanitizer()
    {
        // Worst-case network: every high-risk control in its insecure state so each
        // Critical/Warning branch (and its FixCommand) is emitted.
        var state = new NetworkPostureAnalyzer.NetworkState
        {
            ListeningPorts =
            {
                new NetworkPostureAnalyzer.ListeningPort(445, "System"),
                new NetworkPostureAnalyzer.ListeningPort(3389, "svchost"),
                new NetworkPostureAnalyzer.ListeningPort(23, "telnet"),
            },
            Smbv1 = NetworkPostureAnalyzer.Toggle.Enabled,
            SmbSigningRequired = NetworkPostureAnalyzer.Toggle.Disabled,
            RdpEnabled = true,
            RdpNlaEnabled = false,                 // RDP-without-NLA critical
            WinRmRunning = true,                   // WinRM disable fix
            PublicNetworks = { "Coffee Shop WiFi" },
            ActiveNetworkCount = 1,
            WiFiConnected = true,
            WiFiSsid = "FreeWiFi",
            WiFiAuth = "Open",                     // open Wi-Fi critical
            Llmnr = NetworkPostureAnalyzer.Toggle.Enabled,   // LLMNR reg-add fix
            NetBiosEnabledAdapters = { "Ethernet0" },        // NetBIOS disable fix
            NetBiosAdapterCount = 1,
            WpadHardened = NetworkPostureAnalyzer.Toggle.Disabled, // WPAD Set-ItemProperty fix
            TeredoActive = true,                   // Teredo disable fix
        };

        var findings = NetworkPostureAnalyzer.Analyze(state);
        // SMBv1, SMB-signing, RDP, WinRM, public-profile, open-WiFi, LLMNR, NetBIOS,
        // WPAD, Teredo, high-risk-ports ⇒ well over 9 fix commands.
        AssertAllFixCommandsSanitizerSafe(findings, minExpected: 9);
    }

    [Fact]
    public void PowerShellSecurityAnalyzer_AllFixCommands_SurviveSanitizer()
    {
        // Worst-case PowerShell posture: insecure execution policy, all logging off,
        // v2 engine present, AMSI missing, WinRM with a wildcard TrustedHosts and
        // public exposure — forces every remediation branch.
        var state = new PowerShellSecurityAnalyzer.PowerShellState
        {
            EffectivePolicy = "Bypass",
            MachinePolicy = "Bypass",              // GPO-forced insecure policy warning
            ScriptBlockLoggingEnabled = false,     // reg fix
            ModuleLoggingEnabled = false,          // reg fix
            TranscriptionEnabled = false,          // reg fix
            LanguageMode = "FullLanguage",
            V2EngineInstalled = true,              // Disable-WindowsOptionalFeature fix
            AmsiProviderRegistered = false,        // AMSI critical
            WinRmRunning = true,
            WinRmTrustedHosts = { "*" },           // wildcard TrustedHosts critical fix
            WinRmPublicAccess = true,              // public WinRM firewall fix
        };

        var findings = PowerShellSecurityAnalyzer.Analyze(state);
        // exec-policy, script-block, module, transcription, v2, AMSI, trustedhosts,
        // public-winrm ⇒ ≥ 6 fix commands.
        AssertAllFixCommandsSanitizerSafe(findings, minExpected: 6);
    }

    [Fact]
    public void UsbAnalyzer_AllFixCommands_SurviveSanitizer()
    {
        // Worst-case USB posture: AutoRun not fully disabled, AutoPlay on, no
        // write-protect, no BitLocker-to-Go enforcement, mass storage allowed —
        // forces every remediation branch.
        var state = new UsbAnalyzer.UsbState
        {
            NoDriveTypeAutoRun = null,             // AutoRun Set-ItemProperty fix
            AutoPlayDisabled = false,              // AutoPlay Set-ItemProperty fix
            UsbWriteProtected = false,             // write-protect reg-add fix
            DenyRemovableDevices = false,
            UsbStorStartValue = 3,                 // mass storage allowed (info, no fix)
            RdvDenyWriteAccess = false,            // BitLocker-to-Go fix (gpedit comment)
            UsbDeviceCount = 0,
            RequireRemovableEncryption = false,
        };

        var findings = UsbAnalyzer.Analyze(state);
        // AutoRun + AutoPlay + write-protect are the three real executable fixes.
        AssertAllFixCommandsSanitizerSafe(findings, minExpected: 3);
    }

    [Fact]
    public void BluetoothAudit_AllFixCommands_SurviveSanitizer()
    {
        // Worst-case Bluetooth posture: radio present but disabled with the support
        // service still running ("Service Running Without Radio" warning + its fix).
        // BluetoothAudit uses the instance AnalyzeState(state, result) shape rather
        // than a static Analyze(state), so build a result and read its findings.
        var audit = new BluetoothAudit();
        var result = new WinSentinel.Core.Models.AuditResult
        {
            ModuleName = audit.Name,
            Category = audit.Category,
        };
        var state = new BluetoothAudit.BluetoothState
        {
            RadioPresent = true,
            RadioEnabled = false,
            BluetoothServiceState = BluetoothAudit.ServiceRunState.Running,
        };

        audit.AnalyzeState(state, result);
        // The bthserv stop+disable fix is the one executable remediation in this state.
        AssertAllFixCommandsSanitizerSafe(result.Findings, minExpected: 1);
    }

    [Fact]
    public void EncryptionAnalyzer_CertificateFixCommands_SurviveSanitizer()
    {
        // Worst-case personal certificate store: every problem category present so
        // each warning branch (and its FixCommand) in BuildCertificateFindings fires.
        var summary = new EncryptionAnalyzer.CertStoreSummary
        {
            Total = 4,
            Expired = 1,
            ExpiringSoon = 1,
            WeakKey = 1,
            WeakSignature = 1,
        };

        var findings = EncryptionAnalyzer.BuildCertificateFindings(summary);
        // expired + expiring-soon + weak-key + weak-signature ⇒ 4 fix commands.
        AssertAllFixCommandsSanitizerSafe(findings, minExpected: 4);
    }

    [Fact]
    public void AttackSurfaceReductionAnalyzer_AllFixCommands_SurviveSanitizer()
    {
        // Worst-case ASR posture: no rules configured at all → the Critical
        // "ASR disabled" branch fires and attaches the enable-all fix command.
        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(null, null);
        Assert.NotNull(finding);
        AssertAllFixCommandsSanitizerSafe(new[] { finding! }, minExpected: 1);
    }

    [Theory]
    [InlineData(DefenderAnalyzer.CfaDisabled)]       // Warning + fix
    [InlineData(DefenderAnalyzer.CfaAudit)]          // Warning + fix
    [InlineData(DefenderAnalyzer.CfaBlockDiskOnly)]  // Warning + fix
    [InlineData(DefenderAnalyzer.CfaAuditDiskOnly)]  // Warning + fix
    public void DefenderAnalyzer_ControlledFolderAccessFix_SurvivesSanitizer(int cfaState)
    {
        // Every non-Block CFA state attaches the Set-MpPreference enable fix; prove
        // it survives the sanitizer so the Fix button is real, not dead.
        var finding = DefenderAnalyzer.BuildControlledFolderAccessFinding(cfaState);
        Assert.NotNull(finding);
        AssertAllFixCommandsSanitizerSafe(new[] { finding! }, minExpected: 1);
    }

    [Theory]
    [InlineData(DefenderAnalyzer.PuaDisabled)]  // Warning + fix
    [InlineData(DefenderAnalyzer.PuaAudit)]     // Warning + fix
    public void DefenderAnalyzer_PuaProtectionFix_SurvivesSanitizer(int puaState)
    {
        // Every non-Block PUA state attaches the Set-MpPreference -PUAProtection
        // enable fix; prove it survives the sanitizer so the Fix button is real.
        var finding = DefenderAnalyzer.BuildPuaProtectionFinding(puaState);
        Assert.NotNull(finding);
        AssertAllFixCommandsSanitizerSafe(new[] { finding! }, minExpected: 1);
    }
}
