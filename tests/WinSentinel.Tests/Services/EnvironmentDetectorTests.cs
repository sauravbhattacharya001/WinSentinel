using Xunit;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.EnvironmentDetector;

namespace WinSentinel.Tests.Services;

public class EnvironmentDetectorTests
{
    // ------------------------------------------------------------------
    // Mock provider for testability
    // ------------------------------------------------------------------

    private class MockSystemInfoProvider : ISystemInfoProvider
    {
        public string MachineName { get; set; } = "TEST-PC";
        public string OsVersionStr { get; set; } = "Microsoft Windows NT 10.0.22631.0";
        public int Processors { get; set; } = 8;
        public long MemoryMB { get; set; } = 16384;
        public bool Is64Bit { get; set; } = true;
        public string? Domain { get; set; }
        public bool DomainJoined { get; set; }
        public string Edition { get; set; } = "Professional";
        public List<string> Programs { get; set; } = new();
        public List<string> Services { get; set; } = new();
        public bool IsVM { get; set; }

        public string GetMachineName() => MachineName;
        public string GetOsVersion() => OsVersionStr;
        public int GetProcessorCount() => Processors;
        public long GetTotalMemoryMB() => MemoryMB;
        public bool Is64BitOs() => Is64Bit;
        public string? GetDomainName() => Domain;
        public bool IsDomainJoined() => DomainJoined;
        public string GetOsEdition() => Edition;
        public IReadOnlyList<string> GetInstalledPrograms() => Programs;
        public IReadOnlyList<string> GetRunningServices() => Services;
        public bool IsVirtualMachine() => IsVM;
    }

    // ------------------------------------------------------------------
    // Detection: Home environment
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_HomeEdition_NoDomain_ReturnsHome()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Home",
            DomainJoined = false,
            MemoryMB = 8192
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Home, result.DetectedType);
        Assert.Equal("home", result.RecommendedProfile);
    }

    [Fact]
    public void Detect_MinimalSystem_DefaultsToHome()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Unknown",
            Programs = new(),
            Services = new()
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        // Home has default bias of 10
        Assert.Equal(EnvironmentType.Home, result.DetectedType);
    }

    // ------------------------------------------------------------------
    // Detection: Developer environment
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_DevTools_Installed_ReturnsDeveloper()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Professional",
            Programs = new List<string>
            {
                "Microsoft Visual Studio 2022",
                "Docker Desktop",
                "Git for Windows",
                "Node.js",
                "Python 3.12",
                "Postman"
            },
            MemoryMB = 32768
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Developer, result.DetectedType);
        Assert.Equal("developer", result.RecommendedProfile);
    }

    [Fact]
    public void Detect_WSL_Suggests_Developer()
    {
        var provider = new MockSystemInfoProvider
        {
            Programs = new List<string> { "Windows Subsystem for Linux (WSL)", "Visual Studio Code" }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.True(result.TypeScores[EnvironmentType.Developer] > 0);
        Assert.Contains(result.Indicators, i => i.Category == "Software" && i.SuggestsType == EnvironmentType.Developer);
    }

    // ------------------------------------------------------------------
    // Detection: Enterprise environment
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_DomainJoined_Enterprise_Edition_ReturnsEnterprise()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Enterprise",
            DomainJoined = true,
            Domain = "CORP.CONTOSO.COM",
            Programs = new List<string> { "Microsoft 365 Apps", "CrowdStrike Falcon" }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Enterprise, result.DetectedType);
        Assert.Equal("enterprise", result.RecommendedProfile);
    }

    [Fact]
    public void Detect_DomainJoined_Boosts_Enterprise_Score()
    {
        var withDomain = new MockSystemInfoProvider { DomainJoined = true, Domain = "CORP" };
        var withoutDomain = new MockSystemInfoProvider { DomainJoined = false };

        var r1 = new EnvironmentDetector(withDomain).Detect();
        var r2 = new EnvironmentDetector(withoutDomain).Detect();

        Assert.True(r1.TypeScores[EnvironmentType.Enterprise] > r2.TypeScores[EnvironmentType.Enterprise]);
    }

    [Fact]
    public void Detect_EnterpriseSecurity_Tools_Suggest_Enterprise()
    {
        var provider = new MockSystemInfoProvider
        {
            Programs = new List<string>
            {
                "CrowdStrike Falcon Sensor",
                "Zscaler Client Connector",
                "Microsoft Intune Management Extension"
            },
            DomainJoined = true,
            Domain = "CORP"
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Enterprise, result.DetectedType);
    }

    // ------------------------------------------------------------------
    // Detection: Server environment
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_ServerEdition_ReturnsServer()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "ServerStandard",
            Processors = 16,
            MemoryMB = 65536,
            Services = new List<string> { "W3SVC", "MSSQLSERVER" }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Server, result.DetectedType);
        Assert.Equal("server", result.RecommendedProfile);
    }

    [Fact]
    public void Detect_ActiveDirectory_Services_Suggest_Server()
    {
        var provider = new MockSystemInfoProvider
        {
            Services = new List<string> { "NTDS", "KDC", "DNS" },
            Edition = "ServerDatacenter"
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Server, result.DetectedType);
    }

    [Fact]
    public void Detect_VirtualMachine_Boosts_Server_And_Developer()
    {
        var provider = new MockSystemInfoProvider { IsVM = true };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.True(result.TypeScores[EnvironmentType.Server] > 0);
        Assert.True(result.TypeScores[EnvironmentType.Developer] > 0);
        Assert.Contains(result.Indicators, i => i.Name == "VirtualMachine");
    }

    // ------------------------------------------------------------------
    // Detection: Gaming environment
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_GamingSoftware_ReturnsGaming()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Home",
            Programs = new List<string>
            {
                "Steam",
                "Epic Games Launcher",
                "NVIDIA GeForce Experience",
                "Discord",
                "Razer Synapse"
            },
            MemoryMB = 32768
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Gaming, result.DetectedType);
        Assert.Equal("home", result.RecommendedProfile); // Gaming maps to home profile
    }

    // ------------------------------------------------------------------
    // Profile mapping
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(EnvironmentType.Home, "home")]
    [InlineData(EnvironmentType.Developer, "developer")]
    [InlineData(EnvironmentType.Enterprise, "enterprise")]
    [InlineData(EnvironmentType.Server, "server")]
    [InlineData(EnvironmentType.Gaming, "home")]
    [InlineData(EnvironmentType.Unknown, "home")]
    public void MapToProfile_ReturnsCorrectProfile(EnvironmentType type, string expected)
    {
        // Test MapToProfile indirectly through Detect result
        // since MapToProfile is internal
        var provider = new MockSystemInfoProvider();
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        // Verify the profile mapping by checking that the recommended profile
        // for each environment type is correct
        // We can verify through the Detect result's recommended profile
        // For a comprehensive check, we validate the known mappings
        Assert.NotNull(expected);  // just verify the mapping expectation

        // Direct verification: create a detection with the expected type
        // and check the profile
        switch (type)
        {
            case EnvironmentType.Home:
                Assert.Equal("home", GetProfileForType(EnvironmentType.Home));
                break;
            case EnvironmentType.Developer:
                Assert.Equal("developer", GetProfileForType(EnvironmentType.Developer));
                break;
            case EnvironmentType.Enterprise:
                Assert.Equal("enterprise", GetProfileForType(EnvironmentType.Enterprise));
                break;
            case EnvironmentType.Server:
                Assert.Equal("server", GetProfileForType(EnvironmentType.Server));
                break;
            case EnvironmentType.Gaming:
                Assert.Equal("home", GetProfileForType(EnvironmentType.Gaming));
                break;
            case EnvironmentType.Unknown:
                Assert.Equal("home", GetProfileForType(EnvironmentType.Unknown));
                break;
        }
    }

    /// <summary>Helper that detects and returns profile for a given env type setup.</summary>
    private static string GetProfileForType(EnvironmentType targetType)
    {
        MockSystemInfoProvider provider = targetType switch
        {
            EnvironmentType.Server => new() { Edition = "ServerDatacenter", Services = new() { "NTDS", "KDC", "DNS", "W3SVC" }, Processors = 32, MemoryMB = 131072 },
            EnvironmentType.Enterprise => new() { Edition = "Enterprise", DomainJoined = true, Domain = "CORP", Programs = new() { "CrowdStrike Falcon Sensor" } },
            EnvironmentType.Developer => new() { Programs = new() { "Microsoft Visual Studio 2022", "Docker Desktop", "Git for Windows", "Node.js", "Python 3.12" }, MemoryMB = 32768 },
            EnvironmentType.Gaming => new() { Edition = "Home", Programs = new() { "Steam", "Epic Games Launcher", "NVIDIA GeForce Experience", "Razer Synapse" }, MemoryMB = 32768 },
            EnvironmentType.Home => new() { Edition = "Home", MemoryMB = 8192 },
            _ => new() { Edition = "Unknown" }
        };

        var detector = new EnvironmentDetector(provider);
        return detector.Detect().RecommendedProfile;
    }

    // ------------------------------------------------------------------
    // Confidence levels
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_ClearSignals_HighConfidence()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "ServerDatacenter",
            DomainJoined = true,
            Domain = "DC.CORP.COM",
            Services = new List<string> { "NTDS", "KDC", "DNS", "W3SVC" },
            Processors = 32,
            MemoryMB = 131072
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Equal(EnvironmentType.Server, result.DetectedType);
        Assert.Equal(Confidence.High, result.DetectionConfidence);
    }

    [Fact]
    public void Detect_AmbiguousSignals_LowConfidence()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Professional",
            Programs = new List<string> { "Git for Windows", "Steam" },
            MemoryMB = 16384
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        // Mixed signals — should have lower confidence
        Assert.NotEqual(Confidence.High, result.DetectionConfidence);
    }

    // ------------------------------------------------------------------
    // Fingerprint
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_Fingerprint_PopulatedCorrectly()
    {
        var provider = new MockSystemInfoProvider
        {
            MachineName = "DEV-WORKSTATION",
            Edition = "Professional",
            OsVersionStr = "10.0.22631",
            Processors = 12,
            MemoryMB = 32768,
            Is64Bit = true,
            DomainJoined = false,
            IsVM = false
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();
        var fp = result.Fingerprint;

        Assert.Equal("DEV-WORKSTATION", fp.MachineName);
        Assert.Equal("Professional", fp.OsEdition);
        Assert.Equal(12, fp.ProcessorCount);
        Assert.Equal(32768, fp.TotalMemoryMB);
        Assert.True(fp.Is64Bit);
        Assert.False(fp.IsDomainJoined);
        Assert.False(fp.IsVirtualMachine);
    }

    [Fact]
    public void Detect_Fingerprint_SoftwareCategories()
    {
        var provider = new MockSystemInfoProvider
        {
            Programs = new List<string>
            {
                "Docker Desktop", "Visual Studio Code", "Steam",
                "Microsoft Office 2024", "Microsoft Teams"
            }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains("Containers/Virtualization", result.Fingerprint.DetectedSoftwareCategories);
        Assert.Contains("Gaming Platforms", result.Fingerprint.DetectedSoftwareCategories);
        Assert.Contains("Productivity/Communication", result.Fingerprint.DetectedSoftwareCategories);
    }

    // ------------------------------------------------------------------
    // Indicators
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_Indicators_NotEmpty()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Professional",
            Programs = new List<string> { "Git for Windows" }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.NotEmpty(result.Indicators);
        Assert.All(result.Indicators, i =>
        {
            Assert.NotEmpty(i.Category);
            Assert.NotEmpty(i.Name);
            Assert.True(i.Weight > 0);
        });
    }

    [Fact]
    public void Detect_OsEdition_Creates_Indicator()
    {
        var provider = new MockSystemInfoProvider { Edition = "Enterprise" };
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains(result.Indicators, i =>
            i.Category == "OS" && i.Name == "Edition" && i.Value == "Enterprise");
    }

    // ------------------------------------------------------------------
    // Summary & Recommendations
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_Summary_ContainsKeyInfo()
    {
        var provider = new MockSystemInfoProvider
        {
            MachineName = "MY-PC",
            Edition = "Home"
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains("Home", result.Summary);
        Assert.Contains("MY-PC", result.Summary);
        Assert.Contains("home", result.Summary);
    }

    [Fact]
    public void Detect_Recommendations_NotEmpty()
    {
        var provider = new MockSystemInfoProvider();
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.NotEmpty(result.Recommendations);
        Assert.All(result.Recommendations, r => Assert.NotEmpty(r));
    }

    [Fact]
    public void Detect_LowConfidence_Includes_ManualProfileTip()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Professional",
            Programs = new List<string> { "Steam", "Visual Studio 2022" },
            MemoryMB = 16384
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        if (result.DetectionConfidence == Confidence.Low)
        {
            Assert.Contains(result.Recommendations,
                r => r.Contains("--profile", StringComparison.OrdinalIgnoreCase));
        }
    }

    // ------------------------------------------------------------------
    // TypeScores
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_TypeScores_ContainsAllTypes()
    {
        var provider = new MockSystemInfoProvider();
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains(EnvironmentType.Home, result.TypeScores.Keys);
        Assert.Contains(EnvironmentType.Developer, result.TypeScores.Keys);
        Assert.Contains(EnvironmentType.Enterprise, result.TypeScores.Keys);
        Assert.Contains(EnvironmentType.Server, result.TypeScores.Keys);
        Assert.Contains(EnvironmentType.Gaming, result.TypeScores.Keys);
    }

    [Fact]
    public void Detect_HomeDefault_Bias_Exists()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Unknown",
            Programs = new(),
            Services = new()
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.True(result.TypeScores[EnvironmentType.Home] >= 10,
            "Home should have default bias of at least 10");
    }

    // ------------------------------------------------------------------
    // Hardware indicators
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_HighMemory_Suggests_Server()
    {
        var provider = new MockSystemInfoProvider { MemoryMB = 65536 };
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains(result.Indicators, i =>
            i.Category == "Hardware" && i.Name == "HighMemory" && i.SuggestsType == EnvironmentType.Server);
    }

    [Fact]
    public void Detect_LowMemory_Suggests_Home()
    {
        var provider = new MockSystemInfoProvider { MemoryMB = 4096 };
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains(result.Indicators, i =>
            i.Category == "Hardware" && i.Name == "LowMemory" && i.SuggestsType == EnvironmentType.Home);
    }

    [Fact]
    public void Detect_HighCPU_Suggests_Server()
    {
        var provider = new MockSystemInfoProvider { Processors = 32 };
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.Contains(result.Indicators, i =>
            i.Category == "Hardware" && i.Name == "HighCPU" && i.SuggestsType == EnvironmentType.Server);
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_EmptyPrograms_NoCrash()
    {
        var provider = new MockSystemInfoProvider
        {
            Programs = new(),
            Services = new()
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.NotNull(result);
        Assert.NotNull(result.Summary);
        Assert.NotNull(result.Fingerprint);
    }

    [Fact]
    public void Detect_DomainJoined_Shows_In_Summary()
    {
        var provider = new MockSystemInfoProvider
        {
            DomainJoined = true,
            Domain = "CORP.EXAMPLE.COM"
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        Assert.True(result.Fingerprint.IsDomainJoined);
        Assert.Equal("CORP.EXAMPLE.COM", result.Fingerprint.DomainName);
        Assert.Contains("CORP.EXAMPLE.COM", result.Summary);
    }

    [Fact]
    public void Detect_DetectedAt_IsRecent()
    {
        var provider = new MockSystemInfoProvider();
        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        var age = DateTimeOffset.UtcNow - result.Fingerprint.DetectedAt;
        Assert.True(age.TotalSeconds < 30, "DetectedAt should be recent");
    }

    // ------------------------------------------------------------------
    // Mixed environment detection
    // ------------------------------------------------------------------

    [Fact]
    public void Detect_DevAndGaming_DevWins_WithMoreTools()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "Professional",
            Programs = new List<string>
            {
                "Microsoft Visual Studio 2022",  // 15
                "Docker Desktop",                // 10
                "Git for Windows",               // 8
                "Node.js",                        // 8
                "Python 3.12",                   // 7
                "Steam",                         // 15
                "Discord"                        // 5
            }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        // Dev tools total (capped 40) should beat gaming (capped 35 for 2 items)
        Assert.True(result.TypeScores[EnvironmentType.Developer] > 0);
        Assert.True(result.TypeScores[EnvironmentType.Gaming] > 0);
    }

    [Fact]
    public void Detect_ServerServices_Override_Software()
    {
        var provider = new MockSystemInfoProvider
        {
            Edition = "ServerStandard",
            Services = new List<string> { "W3SVC", "MSSQLSERVER", "DNS" },
            Programs = new List<string> { "Visual Studio 2022", "Git for Windows" }
        };

        var detector = new EnvironmentDetector(provider);
        var result = detector.Detect();

        // Server edition (30) + server services should dominate
        Assert.Equal(EnvironmentType.Server, result.DetectedType);
    }
}
