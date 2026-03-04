using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.WifiAudit;

namespace WinSentinel.Tests.Audits;

public class WifiAuditTests
{
    private readonly WifiAudit _audit;

    public WifiAuditTests()
    {
        _audit = new WifiAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "WiFi Security Audit",
        Category = "WiFi"
    };

    private static WifiState MakeSecureState() => new()
    {
        AdapterPresent = true,
        WifiEnabled = true,
        ConnectedNetwork = "MySecureNetwork",
        Profiles = new List<WifiProfile>
        {
            new()
            {
                Name = "MySecureNetwork",
                Authentication = "WPA2PSK",
                Cipher = "CCMP",
                AutoConnect = true,
                IsHidden = false,
                PasswordInCleartext = false,
                MacRandomization = true,
                ConnectionMode = "auto"
            },
            new()
            {
                Name = "WorkNetwork",
                Authentication = "WPA3SAE",
                Cipher = "GCMP256",
                AutoConnect = false,
                IsHidden = false,
                PasswordInCleartext = false,
                MacRandomization = true,
                ConnectionMode = "manual"
            }
        },
        HostedNetworkAllowed = false,
        MacRandomizationEnabled = true,
        WifiSenseEnabled = false,
        HotspotSharingEnabled = false,
        DriverVersion = "22.180.0.4",
        DriverAgeDays = 60
    };

    private static WifiState MakeInsecureState() => new()
    {
        AdapterPresent = true,
        WifiEnabled = true,
        ConnectedNetwork = "FreeWiFi",
        Profiles = new List<WifiProfile>
        {
            new()
            {
                Name = "FreeWiFi",
                Authentication = "Open",
                Cipher = "None",
                AutoConnect = true,
                IsHidden = false,
                PasswordInCleartext = false,
                MacRandomization = false,
                ConnectionMode = "auto"
            },
            new()
            {
                Name = "OldRouter",
                Authentication = "WEP",
                Cipher = "WEP",
                AutoConnect = true,
                IsHidden = false,
                PasswordInCleartext = true,
                MacRandomization = false,
                ConnectionMode = "auto"
            },
            new()
            {
                Name = "HiddenNet",
                Authentication = "WPAPSK",
                Cipher = "TKIP",
                AutoConnect = false,
                IsHidden = true,
                PasswordInCleartext = true,
                MacRandomization = false,
                ConnectionMode = "manual"
            },
            new()
            {
                Name = "starbucks wifi",
                Authentication = "Open",
                Cipher = "None",
                AutoConnect = true,
                IsHidden = false,
                PasswordInCleartext = false,
                MacRandomization = false,
                ConnectionMode = "auto"
            }
        },
        HostedNetworkAllowed = true,
        MacRandomizationEnabled = false,
        WifiSenseEnabled = true,
        HotspotSharingEnabled = true,
        DriverVersion = "18.1.0.1",
        DriverAgeDays = 900
    };

    // ── Module metadata ──

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("WiFi Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("WiFi", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ── No adapter ──

    [Fact]
    public void NoAdapter_ReturnsInfoOnly()
    {
        var state = new WifiState { AdapterPresent = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Single(result.Findings);
        Assert.Equal(Severity.Info, result.Findings[0].Severity);
        Assert.Contains("No WiFi Adapter", result.Findings[0].Title);
    }

    // ── Secure state ──

    [Fact]
    public void SecureState_NoWarningsOrCritical()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void SecureState_HasPassFindings()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass);
    }

    // ── Insecure profiles ──

    [Fact]
    public void InsecureProfiles_Open_CriticalFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "TestOpen", Authentication = "Open", Cipher = "None" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Insecure"));
    }

    [Fact]
    public void InsecureProfiles_WEP_CriticalFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "WepNet", Authentication = "WEP", Cipher = "WEP" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Insecure"));
    }

    [Fact]
    public void InsecureProfiles_Shared_CriticalFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "SharedNet", Authentication = "Shared", Cipher = "WEP" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Insecure"));
    }

    [Fact]
    public void InsecureProfiles_CountInTitle()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Open1", Authentication = "Open" },
                new() { Name = "WEP1", Authentication = "WEP" },
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Insecure WiFi Profiles"));
        Assert.Contains("(2)", finding.Title);
    }

    [Fact]
    public void InsecureProfiles_IncludesDeleteCommand()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "BadNet", Authentication = "Open" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Severity == Severity.Critical);
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("netsh wlan delete profile", finding.FixCommand);
    }

    [Fact]
    public void NoInsecureProfiles_PassFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Secure", Authentication = "WPA2PSK" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("No Insecure"));
    }

    // ── Weak profiles ──

    [Fact]
    public void WeakProfiles_WPAPSK_Warning()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "OldWPA", Authentication = "WPAPSK", Cipher = "TKIP" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Weak"));
    }

    [Fact]
    public void WeakProfiles_WPA_Warning()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "CorpWPA", Authentication = "WPA" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Weak"));
    }

    [Fact]
    public void WPA2PSK_NotWeak()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Good", Authentication = "WPA2PSK" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Weak"));
    }

    // ── Auto-connect to insecure ──

    [Fact]
    public void AutoConnectInsecure_Critical()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "OpenAuto", Authentication = "Open", AutoConnect = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Auto-Connect"));
    }

    [Fact]
    public void AutoConnectInsecure_IncludesSetManualCommand()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "WepAuto", Authentication = "WEP", AutoConnect = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Auto-Connect"));
        Assert.Contains("connectionmode=manual", finding.FixCommand!);
    }

    [Fact]
    public void AutoConnectSecure_NoCritical()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Home", Authentication = "WPA2PSK", AutoConnect = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Auto-Connect") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void ManualConnectInsecure_NoAutoConnectFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "OpenManual", Authentication = "Open", AutoConnect = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Auto-Connect"));
    }

    // ── Hidden network probing ──

    [Fact]
    public void HiddenNetwork_Warning()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "SecretNet", Authentication = "WPA2PSK", IsHidden = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Hidden"));
    }

    [Fact]
    public void NoHiddenNetworks_Pass()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Visible", Authentication = "WPA2PSK", IsHidden = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("No Hidden"));
    }

    [Fact]
    public void HiddenNetwork_CountInTitle()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "H1", Authentication = "WPA2PSK", IsHidden = true },
                new() { Name = "H2", Authentication = "WPA2PSK", IsHidden = true },
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Hidden"));
        Assert.Contains("(2)", finding.Title);
    }

    // ── Password exposure ──

    [Fact]
    public void PasswordExposure_InfoFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Net1", Authentication = "WPA2PSK", PasswordInCleartext = true },
                new() { Name = "Net2", Authentication = "WPA2PSK", PasswordInCleartext = true },
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Passwords Stored"));
    }

    [Fact]
    public void NoPasswordExposure_NoFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Net1", Authentication = "WPA2PSK", PasswordInCleartext = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Passwords Stored"));
    }

    // ── Public networks ──

    [Fact]
    public void PublicNetwork_Detected()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "xfinitywifi", Authentication = "Open", AutoConnect = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Public Network"));
    }

    [Fact]
    public void PublicNetwork_AutoConnect_Warning()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "starbucks wifi", Authentication = "Open", AutoConnect = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Public Network"));
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void PublicNetwork_ManualConnect_Info()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "attwifi", Authentication = "Open", AutoConnect = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Public Network"));
        Assert.Equal(Severity.Info, finding.Severity);
    }

    [Fact]
    public void PublicNetwork_PartialMatch()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Hotel WiFi Room 302", Authentication = "Open", AutoConnect = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Public Network"));
    }

    // ── Excessive profiles ──

    [Fact]
    public void ExcessiveProfiles_Warning()
    {
        var profiles = Enumerable.Range(0, 35)
            .Select(i => new WifiProfile { Name = $"Net{i}", Authentication = "WPA2PSK" })
            .ToList();
        var state = new WifiState { AdapterPresent = true, Profiles = profiles };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Excessive"));
    }

    [Fact]
    public void FewProfiles_Pass()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Home", Authentication = "WPA2PSK" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Saved WiFi Profiles"));
    }

    [Fact]
    public void ExactlyThreshold_NoWarning()
    {
        var profiles = Enumerable.Range(0, ExcessiveProfileThreshold)
            .Select(i => new WifiProfile { Name = $"Net{i}", Authentication = "WPA2PSK" })
            .ToList();
        var state = new WifiState { AdapterPresent = true, Profiles = profiles };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Excessive"));
    }

    // ── Hosted network ──

    [Fact]
    public void HostedNetwork_Allowed_Warning()
    {
        var state = new WifiState { AdapterPresent = true, HostedNetworkAllowed = true };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Hosted Network"));
    }

    [Fact]
    public void HostedNetwork_Disabled_Pass()
    {
        var state = new WifiState { AdapterPresent = true, HostedNetworkAllowed = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Hosted Network"));
    }

    [Fact]
    public void HostedNetwork_Unknown_NoFinding()
    {
        var state = new WifiState { AdapterPresent = true, HostedNetworkAllowed = null };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Hosted Network"));
    }

    // ── MAC randomization ──

    [Fact]
    public void MacRandomization_Disabled_Warning()
    {
        var state = new WifiState { AdapterPresent = true, MacRandomizationEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("MAC Address Randomization Disabled"));
    }

    [Fact]
    public void MacRandomization_Enabled_Pass()
    {
        var state = new WifiState { AdapterPresent = true, MacRandomizationEnabled = true };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("MAC Address Randomization Enabled"));
    }

    [Fact]
    public void PerProfileMacRand_Disabled_Info()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "CafeNet", Authentication = "WPA2PSK", MacRandomization = false }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Per-Profile MAC"));
    }

    [Fact]
    public void PerProfileMacRand_AllEnabled_NoFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Home", Authentication = "WPA2PSK", MacRandomization = true }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Per-Profile MAC"));
    }

    // ── WiFi Sense ──

    [Fact]
    public void WifiSense_Enabled_Warning()
    {
        var state = new WifiState { AdapterPresent = true, WifiSenseEnabled = true };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("WiFi Sense"));
    }

    [Fact]
    public void WifiSense_Disabled_Pass()
    {
        var state = new WifiState { AdapterPresent = true, WifiSenseEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("WiFi Sense"));
    }

    // ── Hotspot sharing ──

    [Fact]
    public void HotspotSharing_Enabled_Warning()
    {
        var state = new WifiState { AdapterPresent = true, HotspotSharingEnabled = true };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Password Sharing Enabled"));
    }

    [Fact]
    public void HotspotSharing_Disabled_Pass()
    {
        var state = new WifiState { AdapterPresent = true, HotspotSharingEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Password Sharing Disabled"));
    }

    // ── Driver age ──

    [Fact]
    public void DriverAge_Old_Warning()
    {
        var state = new WifiState { AdapterPresent = true, DriverAgeDays = 500 };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Driver Outdated"));
    }

    [Fact]
    public void DriverAge_Recent_Pass()
    {
        var state = new WifiState { AdapterPresent = true, DriverAgeDays = 100 };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Driver Up to Date"));
    }

    [Fact]
    public void DriverAge_Unknown_NoFinding()
    {
        var state = new WifiState { AdapterPresent = true, DriverAgeDays = null };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Driver"));
    }

    // ── Current connection ──

    [Fact]
    public void ConnectedToInsecure_Critical()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            ConnectedNetwork = "CafeOpen",
            Profiles = new List<WifiProfile>
            {
                new() { Name = "CafeOpen", Authentication = "Open" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Currently Connected"));
    }

    [Fact]
    public void ConnectedToInsecure_IncludesDisconnectCommand()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            ConnectedNetwork = "OpenNet",
            Profiles = new List<WifiProfile>
            {
                new() { Name = "OpenNet", Authentication = "Open" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Currently Connected"));
        Assert.Contains("disconnect", finding.FixCommand!);
    }

    [Fact]
    public void ConnectedToSecure_NoCriticalConnection()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            ConnectedNetwork = "HomeNet",
            Profiles = new List<WifiProfile>
            {
                new() { Name = "HomeNet", Authentication = "WPA2PSK" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Currently Connected"));
    }

    [Fact]
    public void NotConnected_NoConnectionFinding()
    {
        var state = new WifiState { AdapterPresent = true, ConnectedNetwork = null };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Currently Connected"));
    }

    // ── Insecure state full audit ──

    [Fact]
    public void InsecureState_HasMultipleCriticals()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var criticals = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.True(criticals.Count >= 2, $"Expected ≥2 critical findings, got {criticals.Count}");
    }

    [Fact]
    public void InsecureState_HasMultipleWarnings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var warnings = result.Findings.Where(f => f.Severity == Severity.Warning).ToList();
        Assert.True(warnings.Count >= 4, $"Expected ≥4 warnings, got {warnings.Count}");
    }

    [Fact]
    public void InsecureState_DetectsAllIssues()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Insecure WiFi Profiles"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Auto-Connect"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Hidden"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Hosted Network"));
        Assert.Contains(result.Findings, f => f.Title.Contains("MAC Address Randomization Disabled"));
        Assert.Contains(result.Findings, f => f.Title.Contains("WiFi Sense"));
        Assert.Contains(result.Findings, f => f.Title.Contains("Driver Outdated"));
    }

    // ── Static data ──

    [Fact]
    public void InsecureAuthTypes_ContainsExpected()
    {
        Assert.Contains("Open", WifiAudit.InsecureAuthTypes.Keys);
        Assert.Contains("WEP", WifiAudit.InsecureAuthTypes.Keys);
        Assert.Contains("Shared", WifiAudit.InsecureAuthTypes.Keys);
    }

    [Fact]
    public void WeakAuthTypes_ContainsExpected()
    {
        Assert.Contains("WPAPSK", WifiAudit.WeakAuthTypes.Keys);
        Assert.Contains("WPA", WifiAudit.WeakAuthTypes.Keys);
    }

    [Fact]
    public void KnownPublicNetworks_ContainsCommon()
    {
        Assert.Contains("xfinitywifi", WifiAudit.KnownPublicNetworks);
        Assert.Contains("starbucks wifi", WifiAudit.KnownPublicNetworks);
        Assert.Contains("free wifi", WifiAudit.KnownPublicNetworks);
    }

    [Fact]
    public void InsecureAuthTypes_CaseInsensitive()
    {
        Assert.True(WifiAudit.InsecureAuthTypes.ContainsKey("open"));
        Assert.True(WifiAudit.InsecureAuthTypes.ContainsKey("OPEN"));
        Assert.True(WifiAudit.InsecureAuthTypes.ContainsKey("wep"));
    }

    // ── Edge cases ──

    [Fact]
    public void EmptyProfiles_NoExceptions()
    {
        var state = new WifiState { AdapterPresent = true, Profiles = new List<WifiProfile>() };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public void ConnectedToWEP_Critical()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            ConnectedNetwork = "Legacy",
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Legacy", Authentication = "WEP" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Currently Connected"));
    }

    [Fact]
    public void ConnectedNetwork_NotInProfiles_NoConnectionFinding()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            ConnectedNetwork = "UnknownNet",
            Profiles = new List<WifiProfile>()
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Currently Connected"));
    }

    [Fact]
    public void MultipleAutoConnectInsecure_AllListed()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Open1", Authentication = "Open", AutoConnect = true },
                new() { Name = "Open2", Authentication = "Open", AutoConnect = true },
                new() { Name = "Wep1", Authentication = "WEP", AutoConnect = true },
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Auto-Connect"));
        Assert.Contains("(3)", finding.Title);
    }

    [Fact]
    public void WPA3SAE_NotInsecureOrWeak()
    {
        var state = new WifiState
        {
            AdapterPresent = true,
            Profiles = new List<WifiProfile>
            {
                new() { Name = "Modern", Authentication = "WPA3SAE", Cipher = "GCMP256" }
            }
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Insecure") && f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Weak"));
    }

    [Fact]
    public void DriverAge_ExactlyOneYear_NoWarning()
    {
        var state = new WifiState { AdapterPresent = true, DriverAgeDays = 365 };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Driver Outdated"));
    }

    [Fact]
    public void DriverAge_366Days_Warning()
    {
        var state = new WifiState { AdapterPresent = true, DriverAgeDays = 366 };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Driver Outdated"));
    }
}
