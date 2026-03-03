using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.DnsAudit;

namespace WinSentinel.Tests.Audits;

public class DnsAuditTests
{
    private readonly DnsAudit _audit;

    public DnsAuditTests()
    {
        _audit = new DnsAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "DNS Security Audit",
        Category = "DNS"
    };

    private static DnsState MakeSecureState() => new()
    {
        Adapters = new List<AdapterDns>
        {
            new()
            {
                AdapterName = "Ethernet",
                InterfaceAlias = "Ethernet",
                DnsServers = new List<string> { "1.1.1.1", "1.0.0.1" }
            }
        },
        DohEnabled = true,
        LlmnrEnabled = false,
        NetBiosEnabled = false,
        DnsCacheMaxTtl = 86400,
        HostsFileEntries = new List<HostsEntry>(),
        HostsFileReadable = true,
        HostsFileTotalLines = 5,
    };

    private static DnsState MakeInsecureState() => new()
    {
        Adapters = new List<AdapterDns>
        {
            new()
            {
                AdapterName = "Wi-Fi",
                InterfaceAlias = "Wi-Fi",
                DnsServers = new List<string> { "198.54.117.10" } // suspicious
            },
            new()
            {
                AdapterName = "Ethernet",
                InterfaceAlias = "Ethernet",
                DnsServers = new List<string> { "203.0.113.50" } // unknown
            }
        },
        DohEnabled = false,
        LlmnrEnabled = true,
        NetBiosEnabled = true,
        DnsCacheMaxTtl = 604800, // 7 days
        HostsFileEntries = new List<HostsEntry>
        {
            new() { IpAddress = "1.2.3.4", Hostname = "windowsupdate.microsoft.com", LineNumber = 10 },
            new() { IpAddress = "127.0.0.1", Hostname = "localhost", LineNumber = 1 },
        },
        HostsFileReadable = true,
        HostsFileTotalLines = 15,
    };

    // ─── Module metadata ──────────────────────────────────────────

    [Fact]
    public void Name_ReturnsDnsSecurityAudit()
    {
        Assert.Equal("DNS Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsDns()
    {
        Assert.Equal("DNS", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ─── Secure state (all passing) ───────────────────────────────

    [Fact]
    public void AnalyzeState_SecureConfig_NoWarningsOrCritical()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.True(result.Findings.Count > 0, "Should produce findings");
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
    }

    [Fact]
    public void AnalyzeState_SecureConfig_AllPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.All(result.Findings, f =>
            Assert.True(f.Severity == Severity.Pass || f.Severity == Severity.Info,
                $"Expected Pass/Info but got {f.Severity}: {f.Title}"));
    }

    // ─── Insecure state (multiple issues) ─────────────────────────

    [Fact]
    public void AnalyzeState_InsecureConfig_HasCritical()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.True(result.CriticalCount > 0, "Should have critical findings");
    }

    [Fact]
    public void AnalyzeState_InsecureConfig_HasWarnings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.True(result.WarningCount > 0, "Should have warning findings");
    }

    // ─── DNS server checks ────────────────────────────────────────

    [Fact]
    public void AnalyzeState_SuspiciousDns_Critical()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    InterfaceAlias = "Ethernet",
                    DnsServers = new List<string> { "198.54.117.10" }
                }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var critical = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.Contains(critical, f => f.Title.Contains("Suspicious DNS"));
    }

    [Fact]
    public void AnalyzeState_KnownSecureDns_Pass()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    InterfaceAlias = "Ethernet",
                    DnsServers = new List<string> { "8.8.8.8" }
                }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Trusted DNS"));
    }

    [Fact]
    public void AnalyzeState_UnknownDns_Warning()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    InterfaceAlias = "Ethernet",
                    DnsServers = new List<string> { "203.0.113.50" }
                }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Unknown DNS"));
    }

    [Fact]
    public void AnalyzeState_PrivateDns_Info()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    InterfaceAlias = "Ethernet",
                    DnsServers = new List<string> { "192.168.1.1" }
                }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Private DNS"));
    }

    [Fact]
    public void AnalyzeState_NoAdapters_Info()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>(),
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("No DNS Adapters"));
    }

    [Theory]
    [InlineData("1.1.1.1", "Cloudflare")]
    [InlineData("8.8.8.8", "Google")]
    [InlineData("9.9.9.9", "Quad9")]
    [InlineData("208.67.222.222", "OpenDNS")]
    public void AnalyzeState_SecureProvider_PassWithName(string dns, string provider)
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new() { AdapterName = "Test", InterfaceAlias = "Test", DnsServers = new() { dns } }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Description.Contains(provider));
    }

    [Fact]
    public void AnalyzeState_MultipleAdapters_EachChecked()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new() { AdapterName = "Ethernet", InterfaceAlias = "Ethernet", DnsServers = new() { "1.1.1.1" } },
                new() { AdapterName = "Wi-Fi", InterfaceAlias = "Wi-Fi", DnsServers = new() { "198.54.117.10" } },
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Ethernet") && f.Severity == Severity.Pass);
        Assert.Contains(result.Findings, f => f.Title.Contains("Wi-Fi") && f.Severity == Severity.Critical);
    }

    // ─── DoH checks ──────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_DohEnabled_Pass()
    {
        var state = new DnsState { DohEnabled = true, LlmnrEnabled = false, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("DNS-over-HTTPS"));
    }

    [Fact]
    public void AnalyzeState_DohDisabled_Warning()
    {
        var state = new DnsState { DohEnabled = false, LlmnrEnabled = false, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("DNS-over-HTTPS"));
    }

    [Fact]
    public void AnalyzeState_DohNull_Info()
    {
        var state = new DnsState { DohEnabled = null, LlmnrEnabled = false, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("DNS-over-HTTPS"));
    }

    // ─── LLMNR checks ─────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_LlmnrEnabled_Warning()
    {
        var state = new DnsState { LlmnrEnabled = true, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("LLMNR Enabled"));
    }

    [Fact]
    public void AnalyzeState_LlmnrDisabled_Pass()
    {
        var state = new DnsState { LlmnrEnabled = false, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("LLMNR Disabled"));
    }

    [Fact]
    public void AnalyzeState_LlmnrEnabled_HasRemediation()
    {
        var state = new DnsState { LlmnrEnabled = true, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("LLMNR Enabled"));
        Assert.NotNull(finding.Remediation);
        Assert.NotNull(finding.FixCommand);
    }

    // ─── NetBIOS checks ───────────────────────────────────────────

    [Fact]
    public void AnalyzeState_NetBiosEnabled_Warning()
    {
        var state = new DnsState { LlmnrEnabled = false, NetBiosEnabled = true };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("NetBIOS"));
    }

    [Fact]
    public void AnalyzeState_NetBiosDisabled_Pass()
    {
        var state = new DnsState { LlmnrEnabled = false, NetBiosEnabled = false };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("NetBIOS"));
    }

    // ─── Hosts file checks ────────────────────────────────────────

    [Fact]
    public void AnalyzeState_HostsFileUnreadable_Warning()
    {
        var state = new DnsState
        {
            HostsFileReadable = false,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("Hosts File Unreadable"));
    }

    [Fact]
    public void AnalyzeState_HostsFileSuspiciousRedirect_Critical()
    {
        var state = new DnsState
        {
            HostsFileEntries = new List<HostsEntry>
            {
                new() { IpAddress = "5.5.5.5", Hostname = "windowsupdate.microsoft.com", LineNumber = 3 }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Suspicious Hosts"));
    }

    [Fact]
    public void AnalyzeState_HostsFileLocalhostRedirectOk()
    {
        // Redirecting sensitive domain to localhost is allowed (ad-blocking pattern)
        var state = new DnsState
        {
            HostsFileEntries = new List<HostsEntry>
            {
                new() { IpAddress = "127.0.0.1", Hostname = "windowsupdate.microsoft.com", LineNumber = 3 }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_LargeHostsFile_Info()
    {
        var entries = Enumerable.Range(1, 60)
            .Select(i => new HostsEntry { IpAddress = "127.0.0.1", Hostname = $"blocked{i}.com", LineNumber = i })
            .ToList();

        var state = new DnsState
        {
            HostsFileEntries = entries,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Large Hosts File"));
    }

    [Fact]
    public void AnalyzeState_CleanHostsFile_Pass()
    {
        var state = new DnsState
        {
            HostsFileEntries = new List<HostsEntry>
            {
                new() { IpAddress = "127.0.0.1", Hostname = "localhost", LineNumber = 1 }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("Hosts File Clean"));
    }

    // ─── DNS cache TTL checks ─────────────────────────────────────

    [Fact]
    public void AnalyzeState_LowCacheTtl_Info()
    {
        var state = new DnsState
        {
            DnsCacheMaxTtl = 60,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Low DNS Cache TTL"));
    }

    [Fact]
    public void AnalyzeState_HighCacheTtl_Warning()
    {
        var state = new DnsState
        {
            DnsCacheMaxTtl = 604800,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning && f.Title.Contains("High DNS Cache TTL"));
    }

    [Fact]
    public void AnalyzeState_NormalCacheTtl_Pass()
    {
        var state = new DnsState
        {
            DnsCacheMaxTtl = 3600,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Title.Contains("DNS Cache TTL Normal"));
    }

    [Fact]
    public void AnalyzeState_DefaultCacheTtl_Pass()
    {
        var state = new DnsState
        {
            DnsCacheMaxTtl = 0,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Description.Contains("system default"));
    }

    // ─── Fix commands present ─────────────────────────────────────

    [Fact]
    public void AnalyzeState_SuspiciousDns_HasFixCommand()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new() { AdapterName = "Ethernet", InterfaceAlias = "Ethernet", DnsServers = new() { "198.54.117.10" } }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var critical = result.Findings.First(f => f.Severity == Severity.Critical);
        Assert.NotNull(critical.FixCommand);
        Assert.Contains("Set-DnsClientServerAddress", critical.FixCommand);
    }

    [Fact]
    public void AnalyzeState_HighCacheTtl_HasFixCommand()
    {
        var state = new DnsState
        {
            DnsCacheMaxTtl = 604800,
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var warning = result.Findings.First(f => f.Title.Contains("High DNS Cache TTL"));
        Assert.NotNull(warning.FixCommand);
    }

    // ─── Multiple DNS servers per adapter ─────────────────────────

    [Fact]
    public void AnalyzeState_MixedDnsOnSameAdapter()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    InterfaceAlias = "Ethernet",
                    DnsServers = new() { "1.1.1.1", "198.54.117.10" }
                }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass && f.Title.Contains("Trusted"));
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("Suspicious"));
    }

    // ─── Multiple sensitive domain redirects ──────────────────────

    [Fact]
    public void AnalyzeState_MultipleSuspiciousHostsEntries_SingleCritical()
    {
        var state = new DnsState
        {
            HostsFileEntries = new List<HostsEntry>
            {
                new() { IpAddress = "5.5.5.5", Hostname = "windowsupdate.microsoft.com", LineNumber = 3 },
                new() { IpAddress = "6.6.6.6", Hostname = "login.microsoftonline.com", LineNumber = 4 },
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        var critical = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.Single(critical); // grouped into one finding
        Assert.Contains("windowsupdate", critical[0].Description);
        Assert.Contains("login.microsoftonline", critical[0].Description);
    }

    // ─── IPv6 DNS checks ──────────────────────────────────────────

    [Fact]
    public void AnalyzeState_IPv6SecureDns_Pass()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new() { AdapterName = "Ethernet", InterfaceAlias = "Ethernet", DnsServers = new() { "2606:4700:4700::1111" } }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass && f.Description.Contains("Cloudflare"));
    }

    // ─── Full insecure state finding count ────────────────────────

    [Fact]
    public void AnalyzeState_FullInsecureState_AtLeastSixFindings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // DNS servers (2 adapters) + DoH + LLMNR + NetBIOS + hosts + cache = 7+
        Assert.True(result.Findings.Count >= 6,
            $"Expected ≥6 findings but got {result.Findings.Count}");
    }

    // ─── All findings have category ───────────────────────────────

    [Fact]
    public void AnalyzeState_AllFindingsHaveCategory()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.All(result.Findings, f =>
            Assert.Equal("DNS", f.Category));
    }

    // ─── Static data ──────────────────────────────────────────────

    [Fact]
    public void KnownSecureDns_ContainsExpectedProviders()
    {
        Assert.True(KnownSecureDns.Count >= 10);
        Assert.Contains("1.1.1.1", KnownSecureDns.Keys);
        Assert.Contains("8.8.8.8", KnownSecureDns.Keys);
        Assert.Contains("9.9.9.9", KnownSecureDns.Keys);
    }

    [Fact]
    public void SuspiciousDns_IsNotEmpty()
    {
        Assert.NotEmpty(SuspiciousDns);
    }

    [Fact]
    public void SensitiveDomains_ContainsMicrosoftAndGoogle()
    {
        Assert.Contains("microsoft.com", SensitiveDomains);
        Assert.Contains("google.com", SensitiveDomains);
    }

    // ─── 172.x private range ──────────────────────────────────────

    [Fact]
    public void AnalyzeState_172PrivateDns_Info()
    {
        var state = new DnsState
        {
            Adapters = new List<AdapterDns>
            {
                new() { AdapterName = "VPN", InterfaceAlias = "VPN", DnsServers = new() { "172.16.0.1" } }
            },
            LlmnrEnabled = false,
            NetBiosEnabled = false,
        };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info && f.Title.Contains("Private DNS"));
    }
}
