using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.NetworkPostureAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for the pure <see cref="NetworkPostureAnalyzer"/>.
///
/// <see cref="NetworkAuditTests"/> already exercises the module end-to-end against
/// the live system; this suite targets the analyzer's own surface directly with
/// synthetic <see cref="NetworkState"/> instances so every classification threshold
/// (high-risk ports, SMBv1/signing, RDP+NLA, the Wi-Fi WEP/WPA matrix, LLMNR +
/// NetBIOS, the duplicate-MAC ARP heuristic, global IPv6 / Teredo) is pinned without
/// touching PowerShell, netsh, cmd, WMI, or the registry.
/// </summary>
public class NetworkPostureAnalyzerTests
{
    private static ListeningPort Port(int p, string proc = "svc") => new(p, proc);

    private static NetworkState SecureState() => new()
    {
        ListeningPorts = new() { Port(80, "svchost"), Port(443, "svchost") },
        Smbv1 = Toggle.Disabled,
        SmbSigningRequired = Toggle.Enabled,
        RdpEnabled = false,
        WinRmRunning = false,
        ActiveNetworkCount = 1,
        WiFiConnected = true,
        WiFiSsid = "HomeNet",
        WiFiAuth = "WPA3-Personal",
        WiFiCipher = "CCMP",
        Llmnr = Toggle.Disabled,
        NetBiosAdapterCount = 1,
    };

    private static NetworkState InsecureState() => new()
    {
        ListeningPorts = new() { Port(445, "System"), Port(3389, "svchost"), Port(23, "tlntsvr") },
        Smbv1 = Toggle.Enabled,
        SmbSigningRequired = Toggle.Disabled,
        RdpEnabled = true,
        RdpNlaEnabled = false,
        WinRmRunning = true,
        PublicNetworks = new() { "CoffeeShop" },
        ActiveNetworkCount = 1,
        WiFiConnected = true,
        WiFiSsid = "FreeWiFi",
        WiFiAuth = "Open",
        Llmnr = Toggle.Enabled,
        NetBiosEnabledAdapters = new() { "Intel(R) Ethernet" },
        NetBiosAdapterCount = 1,
        ArpEntries = new() { new("192.168.1.1", "aa-bb-cc-dd-ee-ff"), new("192.168.1.2", "aa-bb-cc-dd-ee-ff") },
    };

    private static bool Has(IEnumerable<Finding> f, Severity sev, string titleContains) =>
        f.Any(x => x.Severity == sev && x.Title.Contains(titleContains, StringComparison.OrdinalIgnoreCase));

    // ---- Analyze (aggregate) -------------------------------------------------

    [Fact]
    public void Analyze_NullState_Throws() =>
        Assert.Throws<ArgumentNullException>(() => Analyze(null!));

    [Fact]
    public void Analyze_SecureState_HasNoCriticals()
    {
        var f = Analyze(SecureState());
        Assert.DoesNotContain(f, x => x.Severity == Severity.Critical);
        Assert.NotEmpty(f);
    }

    [Fact]
    public void Analyze_InsecureState_RaisesExpectedCriticals()
    {
        var f = Analyze(InsecureState());
        Assert.True(Has(f, Severity.Critical, "SMBv1"));
        Assert.True(Has(f, Severity.Critical, "RDP Enabled Without NLA"));
        Assert.True(Has(f, Severity.Critical, "Open Wi-Fi"));
    }

    [Fact]
    public void Analyze_EveryFinding_HasCategoryTitleDescription()
    {
        foreach (var find in Analyze(InsecureState()))
        {
            Assert.Equal(Category, find.Category);
            Assert.False(string.IsNullOrWhiteSpace(find.Title));
            Assert.False(string.IsNullOrWhiteSpace(find.Description));
        }
    }

    // ---- Listening ports -----------------------------------------------------

    [Fact]
    public void Ports_FlagsHighRiskAndAlwaysCountsTotal()
    {
        var f = CheckListeningPorts(new NetworkState
        {
            ListeningPorts = new() { Port(445, "System"), Port(8080, "node"), Port(3389, "svc") },
        });
        Assert.True(Has(f, Severity.Warning, "High-Risk Ports Listening (2)"));
        Assert.True(Has(f, Severity.Info, "Total Listening Ports: 3"));
    }

    [Fact]
    public void Ports_NoneHighRisk_Passes()
    {
        var f = CheckListeningPorts(new NetworkState { ListeningPorts = new() { Port(80), Port(443) } });
        Assert.True(Has(f, Severity.Pass, "No Common High-Risk Ports"));
        Assert.True(Has(f, Severity.Info, "Total Listening Ports: 2"));
    }

    [Fact]
    public void Ports_Empty_PassesWithZeroTotal()
    {
        var f = CheckListeningPorts(new NetworkState());
        Assert.True(Has(f, Severity.Pass, "No Common High-Risk Ports"));
        Assert.True(Has(f, Severity.Info, "Total Listening Ports: 0"));
    }

    [Theory]
    [InlineData(21)]
    [InlineData(23)]
    [InlineData(135)]
    [InlineData(139)]
    [InlineData(445)]
    [InlineData(1433)]
    [InlineData(3389)]
    [InlineData(5985)]
    public void Ports_KnownHighRiskPortsAreFlagged(int port)
    {
        Assert.Contains(port, HighRiskPorts);
        var f = CheckListeningPorts(new NetworkState { ListeningPorts = new() { Port(port) } });
        Assert.True(Has(f, Severity.Warning, "High-Risk Ports Listening"));
    }

    [Fact]
    public void Ports_FixCommandPresentOnHighRiskWarning()
    {
        var f = CheckListeningPorts(new NetworkState { ListeningPorts = new() { Port(445) } });
        var w = f.Single(x => x.Severity == Severity.Warning);
        Assert.False(string.IsNullOrWhiteSpace(w.FixCommand));
    }

    // ---- SMB -----------------------------------------------------------------

    [Fact]
    public void Smb_V1Enabled_IsCriticalWithFix()
    {
        var f = CheckSmb(new NetworkState { Smbv1 = Toggle.Enabled });
        var c = f.Single(x => x.Title.Contains("SMBv1"));
        Assert.Equal(Severity.Critical, c.Severity);
        Assert.False(string.IsNullOrWhiteSpace(c.FixCommand));
    }

    [Fact]
    public void Smb_V1Disabled_Passes()
    {
        var f = CheckSmb(new NetworkState { Smbv1 = Toggle.Disabled });
        Assert.True(Has(f, Severity.Pass, "SMBv1 Protocol Disabled"));
    }

    [Fact]
    public void Smb_UnknownStates_EmitNothing() =>
        Assert.Empty(CheckSmb(new NetworkState()));

    [Fact]
    public void Smb_SigningNotRequired_Warns()
    {
        var f = CheckSmb(new NetworkState { SmbSigningRequired = Toggle.Disabled });
        Assert.True(Has(f, Severity.Warning, "SMB Signing Not Required"));
    }

    [Fact]
    public void Smb_SigningRequired_Passes()
    {
        var f = CheckSmb(new NetworkState { SmbSigningRequired = Toggle.Enabled });
        Assert.True(Has(f, Severity.Pass, "SMB Signing Required"));
    }

    [Fact]
    public void Smb_NonDefaultShares_AreReported()
    {
        var f = CheckSmb(new NetworkState { NonDefaultShares = new() { "Finance", "HR" } });
        var info = f.Single(x => x.Title.Contains("Non-Default SMB Shares"));
        Assert.Contains("Finance", info.Description);
        Assert.Contains("HR", info.Description);
    }

    // ---- RDP -----------------------------------------------------------------

    [Fact]
    public void Rdp_Disabled_Passes()
    {
        var f = CheckRdp(new NetworkState { RdpEnabled = false });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("RDP Disabled", f.Title);
    }

    [Fact]
    public void Rdp_EnabledWithoutNla_IsCriticalWithFix()
    {
        var f = CheckRdp(new NetworkState { RdpEnabled = true, RdpNlaEnabled = false });
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("Without NLA", f.Title);
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Rdp_EnabledWithNla_IsInfo()
    {
        var f = CheckRdp(new NetworkState { RdpEnabled = true, RdpNlaEnabled = true });
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("with NLA", f.Title);
    }

    // ---- WinRM ---------------------------------------------------------------

    [Fact]
    public void WinRm_Running_Warns() =>
        Assert.Equal(Severity.Warning, CheckWinRm(new NetworkState { WinRmRunning = true }).Severity);

    [Fact]
    public void WinRm_Stopped_Passes() =>
        Assert.Equal(Severity.Pass, CheckWinRm(new NetworkState { WinRmRunning = false }).Severity);

    // ---- DNS -----------------------------------------------------------------

    [Fact]
    public void Dns_None_ReturnsNull() =>
        Assert.Null(CheckDns(new NetworkState()));

    [Fact]
    public void Dns_Servers_ReportedAsInfo()
    {
        var f = CheckDns(new NetworkState { DnsServers = new() { "1.1.1.1", "8.8.8.8" } });
        Assert.NotNull(f);
        Assert.Equal(Severity.Info, f!.Severity);
        Assert.Contains("1.1.1.1", f.Description);
    }

    // ---- Network profile -----------------------------------------------------

    [Fact]
    public void Profile_Public_Warns()
    {
        var f = CheckNetworkProfile(new NetworkState { PublicNetworks = new() { "Airport" }, ActiveNetworkCount = 1 });
        Assert.True(Has(f, Severity.Warning, "Public Network Profile Active (1)"));
    }

    [Fact]
    public void Profile_AllPrivate_Passes()
    {
        var f = CheckNetworkProfile(new NetworkState { ActiveNetworkCount = 2 });
        Assert.True(Has(f, Severity.Pass, "Private/Domain"));
    }

    [Fact]
    public void Profile_NoActiveConnections_EmitsNothing() =>
        Assert.Empty(CheckNetworkProfile(new NetworkState { ActiveNetworkCount = 0 }));

    // ---- Wi-Fi ---------------------------------------------------------------

    [Fact]
    public void WiFi_NoStateCollected_ReturnsNull() =>
        Assert.Null(CheckWiFi(new NetworkState()));

    [Fact]
    public void WiFi_RadioPresentButIdle_IsInfoNotConnected()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = false, WiFiSsid = "Prev", WiFiAuth = "WPA2-Personal" });
        Assert.NotNull(f);
        Assert.Equal(Severity.Info, f!.Severity);
        Assert.Contains("Not Connected", f.Title);
    }

    [Fact]
    public void WiFi_Open_IsCritical()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Free", WiFiAuth = "Open" });
        Assert.Equal(Severity.Critical, f!.Severity);
        Assert.Contains("Open Wi-Fi", f.Title);
    }

    [Fact]
    public void WiFi_Wep_IsCritical()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Old", WiFiAuth = "WEP" });
        Assert.Equal(Severity.Critical, f!.Severity);
        Assert.Contains("WEP", f.Title);
    }

    [Fact]
    public void WiFi_Wpa1_Warns()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Legacy", WiFiAuth = "WPA-Personal" });
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("WPA1", f.Title);
    }

    [Theory]
    [InlineData("WPA-Enterprise")] // 802.1X WPA1 -- netsh's enterprise spelling
    [InlineData("WPA")]            // bare "WPA" with no -Personal/-Enterprise suffix
    public void WiFi_Wpa1Variants_Warn(string auth)
    {
        // Regression: only "WPA-Personal" used to be flagged, so a WPA1-Enterprise
        // (or bare "WPA") network fell through to the benign generic Info branch
        // even though WPA1/TKIP is deprecated and vulnerable. Every WPA1 flavour
        // must warn.
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Legacy", WiFiAuth = auth });
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("WPA1", f.Title);
    }

    [Fact]
    public void WiFi_Wpa2Tkip_Warns()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA2-Personal", WiFiCipher = "TKIP" });
        Assert.Equal(Severity.Warning, f!.Severity);
        Assert.Contains("WPA2-TKIP", f.Title);
    }

    [Fact]
    public void WiFi_Wpa2Aes_Passes()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA2-Personal", WiFiCipher = "CCMP" });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("WPA2-AES", f.Title);
    }

    [Theory]
    [InlineData("AES")]
    [InlineData("CCMP")]
    [InlineData("AES-CCMP")]
    public void WiFi_Wpa2ExplicitAesCipher_ClaimsAes(string cipher)
    {
        // When netsh actually reports an AES/CCMP cipher we are entitled to assert
        // the strong "WPA2-AES" posture in the finding title.
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA2-Personal", WiFiCipher = cipher });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("WPA2-AES", f.Title);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("N/A")]
    public void WiFi_Wpa2UnknownCipher_DoesNotClaimAes(string? cipher)
    {
        // Regression: a WPA2 network whose cipher could not be read used to be
        // reported as "WPA2-AES Wi-Fi Security" with "Cipher: N/A" -- a confident
        // AES claim the analyzer never actually verified (the link could be running
        // TKIP). WPA2 itself is still acceptable, so this stays a Pass, but the
        // title must NOT overstate the cipher as AES.
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA2-Personal", WiFiCipher = cipher });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.DoesNotContain("AES", f.Title);
        Assert.Contains("WPA2", f.Title);
    }

    [Fact]
    public void WiFi_Wpa2UnknownCipher_BodyNotesCipherUnverified()
    {
        // The remediation/description should make the uncertainty explicit so a user
        // does not read the Pass as "AES confirmed".
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA2-Personal" });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("could not", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WiFi_Wpa3_Passes()
    {
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Home", WiFiAuth = "WPA3-Personal", WiFiCipher = "CCMP" });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.Contains("WPA3", f.Title);
    }

    [Fact]
    public void WiFi_Enterprise_ClassifiedAsWpa2Pass()
    {
        // "WPA2-Enterprise" contains "WPA2"; with no cipher reported it still passes
        // (WPA2 is acceptable) but must not be mislabelled as verified "WPA2-AES".
        var f = CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "Ent", WiFiAuth = "WPA2-Enterprise" });
        Assert.Equal(Severity.Pass, f!.Severity);
        Assert.DoesNotContain("AES", f.Title);
    }

    [Fact]
    public void WiFi_ConnectedMissingAuth_ReturnsNull() =>
        Assert.Null(CheckWiFi(new NetworkState { WiFiConnected = true, WiFiSsid = "X", WiFiAuth = null }));

    // ---- LLMNR + NetBIOS -----------------------------------------------------

    [Fact]
    public void Llmnr_Disabled_Passes()
    {
        var f = CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Disabled });
        Assert.True(Has(f, Severity.Pass, "LLMNR Disabled"));
    }

    [Fact]
    public void Llmnr_EnabledOrUnknown_Warns()
    {
        Assert.True(Has(CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Enabled }), Severity.Warning, "LLMNR Enabled"));
        Assert.True(Has(CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Unknown }), Severity.Warning, "LLMNR Enabled"));
    }

    [Fact]
    public void Llmnr_WarningHasFixCommand()
    {
        var w = CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Enabled })
            .Single(x => x.Title.Contains("LLMNR Enabled"));
        Assert.False(string.IsNullOrWhiteSpace(w.FixCommand));
    }

    [Fact]
    public void NetBios_EnabledAdapters_WarnWithFix()
    {
        var f = CheckLlmnrNetBios(new NetworkState
        {
            Llmnr = Toggle.Disabled,
            NetBiosEnabledAdapters = new() { "Adapter A", "Adapter B" },
            NetBiosAdapterCount = 2,
        });
        var w = f.Single(x => x.Title.Contains("NetBIOS over TCP/IP Enabled"));
        Assert.Equal(Severity.Warning, w.Severity);
        Assert.Contains("(2 adapter(s))", w.Title);
        Assert.False(string.IsNullOrWhiteSpace(w.FixCommand));
    }

    [Fact]
    public void NetBios_AllDisabledWithAdaptersSeen_Passes()
    {
        var f = CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Disabled, NetBiosAdapterCount = 3 });
        Assert.True(Has(f, Severity.Pass, "NetBIOS over TCP/IP Disabled"));
    }

    [Fact]
    public void NetBios_NoAdaptersSeen_EmitsOnlyLlmnr()
    {
        var f = CheckLlmnrNetBios(new NetworkState { Llmnr = Toggle.Disabled, NetBiosAdapterCount = 0 });
        Assert.DoesNotContain(f, x => x.Title.Contains("NetBIOS"));
    }

    // ---- ARP -----------------------------------------------------------------

    [Fact]
    public void Arp_DuplicateMac_Warns()
    {
        var f = CheckArp(new NetworkState
        {
            ArpEntries = new() { new("10.0.0.1", "de-ad-be-ef-00-01"), new("10.0.0.9", "de-ad-be-ef-00-01") },
        });
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("Duplicate MAC", f.Title);
        Assert.Contains("de-ad-be-ef-00-01", f.Description);
    }

    [Fact]
    public void Arp_UniqueMacs_NoAnomalies()
    {
        var f = CheckArp(new NetworkState
        {
            ArpEntries = new() { new("10.0.0.1", "aa-aa-aa-aa-aa-01"), new("10.0.0.2", "aa-aa-aa-aa-aa-02") },
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("No Anomalies", f.Title);
    }

    [Fact]
    public void Arp_IgnoresBroadcastAndMulticastMacs()
    {
        var f = CheckArp(new NetworkState
        {
            ArpEntries = new()
            {
                new("255.255.255.255", "ff-ff-ff-ff-ff-ff"),
                new("224.0.0.1", "01-00-5e-00-00-01"),
                new("224.0.0.2", "01-00-5e-00-00-02"),
                new("ff02::1", "33-33-00-00-00-01"),
            },
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Empty", f.Title);
    }

    [Fact]
    public void Arp_IgnoresGroupMacsAcrossMultipleIps_NoFalseSpoofWarning()
    {
        // STP/bridge (01-80-c2) and Cisco CDP (01-00-0c) are group/multicast MACs
        // that legitimately appear against several IPs on a switched network.
        // They must NOT be flagged as duplicate-MAC ARP spoofing.
        var f = CheckArp(new NetworkState
        {
            ArpEntries = new()
            {
                new("10.0.0.1", "01-80-c2-00-00-00"),
                new("10.0.0.2", "01-80-c2-00-00-00"),
                new("10.0.0.3", "01-00-0c-cc-cc-cc"),
                new("10.0.0.4", "01-00-0c-cc-cc-cc"),
            },
        });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.DoesNotContain("Duplicate MAC", f.Title);
    }

    [Fact]
    public void Arp_QueryFailed_PassesUnavailable()
    {
        var f = CheckArp(new NetworkState { ArpQueryFailed = true, ArpError = "access denied" });
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Unavailable", f.Title);
        Assert.Contains("access denied", f.Description);
    }

    [Fact]
    public void Arp_Empty_PassesEmpty()
    {
        var f = CheckArp(new NetworkState());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Contains("Empty", f.Title);
    }

    [Theory]
    [InlineData("ff-ff-ff-ff-ff-ff", true)]   // broadcast
    [InlineData("01-00-5e-12-34-56", true)]   // IPv4 multicast
    [InlineData("33-33-00-00-00-fb", true)]   // IPv6 multicast
    [InlineData("01-80-c2-00-00-00", true)]   // IEEE 802.1D STP / bridge group
    [InlineData("01-80-c2-00-00-0e", true)]   // LLDP
    [InlineData("01-00-0c-cc-cc-cc", true)]   // Cisco CDP/VTP
    [InlineData("09-00-2b-00-00-0f", true)]   // DEC group (odd first octet)
    [InlineData("03-bf-12-34-56-78", true)]   // arbitrary odd first octet => group
    [InlineData("01:80:c2:00:00:00", true)]   // colon-separated multicast
    [InlineData("0180c2000000", true)]        // contiguous multicast
    [InlineData("aa-bb-cc-dd-ee-ff", false)]  // locally-administered unicast
    [InlineData("02-00-00-00-00-01", false)]  // locally-administered unicast (LSB of first octet = 0)
    [InlineData("00-1a-2b-3c-4d-5e", false)]  // globally-unique unicast
    [InlineData("AA-BB-CC-DD-EE-FF", false)]  // uppercase unicast
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("not-a-mac", false)]          // unparseable first octet => not group
    public void IsBroadcastOrMulticastMac_Classifies(string mac, bool expected) =>
        Assert.Equal(expected, IsBroadcastOrMulticastMac(mac));

    // ---- IPv6 ----------------------------------------------------------------

    [Fact]
    public void IPv6_NoneActive_EmitsNothing() =>
        Assert.Empty(CheckIPv6(new NetworkState()));

    [Fact]
    public void IPv6_GlobalAddresses_ReportedAsInfo()
    {
        var f = CheckIPv6(new NetworkState { GlobalIPv6Addresses = new() { "2001:db8::1", "2001:db8::2" } });
        var info = f.Single(x => x.Title.Contains("Global IPv6"));
        Assert.Equal(Severity.Info, info.Severity);
        Assert.Contains("2001:db8::1", info.Description);
        Assert.Contains("(2)", info.Title);
    }

    [Fact]
    public void IPv6_TeredoActive_Warns()
    {
        var f = CheckIPv6(new NetworkState { TeredoActive = true });
        Assert.True(Has(f, Severity.Warning, "Teredo"));
    }

    [Fact]
    public void IPv6_GlobalAndTeredo_EmitsBoth()
    {
        var f = CheckIPv6(new NetworkState { GlobalIPv6Addresses = new() { "2001:db8::9" }, TeredoActive = true });
        Assert.True(Has(f, Severity.Info, "Global IPv6"));
        Assert.True(Has(f, Severity.Warning, "Teredo"));
    }
}
