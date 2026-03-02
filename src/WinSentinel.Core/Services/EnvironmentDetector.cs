using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Auto-detects the system environment type (Home, Developer, Enterprise, Server, Gaming)
/// by inspecting OS edition, installed software, domain membership, hardware, and running
/// services. Recommends the most appropriate compliance profile and provides a system
/// fingerprint for security context.
/// </summary>
public class EnvironmentDetector
{
    /// <summary>Detected environment classification.</summary>
    public enum EnvironmentType
    {
        Home,
        Developer,
        Enterprise,
        Server,
        Gaming,
        Unknown
    }

    /// <summary>Confidence level of the detection.</summary>
    public enum Confidence
    {
        Low,
        Medium,
        High
    }

    /// <summary>A single detected indicator that contributed to the classification.</summary>
    public record EnvironmentIndicator(
        string Category,
        string Name,
        string Value,
        EnvironmentType SuggestsType,
        int Weight
    );

    /// <summary>Complete environment detection result.</summary>
    public class DetectionResult
    {
        public EnvironmentType DetectedType { get; set; } = EnvironmentType.Unknown;
        public Confidence DetectionConfidence { get; set; } = Confidence.Low;
        public string RecommendedProfile { get; set; } = "home";
        public string Summary { get; set; } = "";
        public SystemFingerprint Fingerprint { get; set; } = new();
        public List<EnvironmentIndicator> Indicators { get; set; } = new();
        public Dictionary<EnvironmentType, int> TypeScores { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
    }

    /// <summary>System fingerprint capturing key hardware/software characteristics.</summary>
    public class SystemFingerprint
    {
        public string MachineName { get; set; } = "";
        public string OsEdition { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public bool IsDomainJoined { get; set; }
        public string? DomainName { get; set; }
        public int ProcessorCount { get; set; }
        public long TotalMemoryMB { get; set; }
        public bool Is64Bit { get; set; }
        public bool IsVirtualMachine { get; set; }
        public List<string> DetectedSoftwareCategories { get; set; } = new();
        public List<string> ActiveServices { get; set; } = new();
        public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.UtcNow;
    }

    // ------------------------------------------------------------------
    // Abstraction layer for testability
    // ------------------------------------------------------------------

    private readonly ISystemInfoProvider _provider;

    /// <summary>Abstraction for system queries — allows mocking in tests.</summary>
    public interface ISystemInfoProvider
    {
        string GetMachineName();
        string GetOsVersion();
        int GetProcessorCount();
        long GetTotalMemoryMB();
        bool Is64BitOs();
        string? GetDomainName();
        bool IsDomainJoined();
        string GetOsEdition();
        IReadOnlyList<string> GetInstalledPrograms();
        IReadOnlyList<string> GetRunningServices();
        bool IsVirtualMachine();
    }

    /// <summary>Default provider using real system APIs.</summary>
    private sealed class WindowsSystemInfoProvider : ISystemInfoProvider
    {
        public string GetMachineName() => Environment.MachineName;

        public string GetOsVersion() => Environment.OSVersion.VersionString;

        public int GetProcessorCount() => Environment.ProcessorCount;

        public long GetTotalMemoryMB()
        {
            try
            {
                // Use GC.GetGCMemoryInfo as a rough proxy (works without P/Invoke)
                var info = GC.GetGCMemoryInfo();
                return info.TotalAvailableMemoryBytes / (1024 * 1024);
            }
            catch
            {
                return 0;
            }
        }

        public bool Is64BitOs() => Environment.Is64BitOperatingSystem;

        public string? GetDomainName()
        {
            try
            {
                return Environment.UserDomainName;
            }
            catch
            {
                return null;
            }
        }

        public bool IsDomainJoined()
        {
            try
            {
                var domain = Environment.UserDomainName;
                var machine = Environment.MachineName;
                return !string.IsNullOrEmpty(domain) &&
                       !domain.Equals(machine, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        public string GetOsEdition()
        {
            try
            {
                return Microsoft.Win32.Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "EditionID", "Unknown")?.ToString() ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        public IReadOnlyList<string> GetInstalledPrograms()
        {
            var programs = new List<string>();
            try
            {
                string[] registryPaths =
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                };

                foreach (var path in registryPaths)
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            var name = subKey?.GetValue("DisplayName")?.ToString();
                            if (!string.IsNullOrWhiteSpace(name))
                                programs.Add(name);
                        }
                        catch { /* skip inaccessible entries */ }
                    }
                }
            }
            catch { /* registry access failed */ }

            return programs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public IReadOnlyList<string> GetRunningServices()
        {
            var services = new List<string>();
            try
            {
                var svcList = System.ServiceProcess.ServiceController.GetServices();
                foreach (var svc in svcList)
                {
                    try
                    {
                        if (svc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                            services.Add(svc.ServiceName);
                        svc.Dispose();
                    }
                    catch
                    {
                        svc.Dispose();
                    }
                }
            }
            catch { /* service enumeration failed */ }

            return services;
        }

        public bool IsVirtualMachine()
        {
            try
            {
                var manufacturer = Microsoft.Win32.Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation",
                    "SystemManufacturer", "")?.ToString() ?? "";

                var vmIndicators = new[] { "VMware", "VirtualBox", "Microsoft Corporation", "QEMU", "Xen", "Hyper-V" };
                return vmIndicators.Any(v => manufacturer.Contains(v, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    public EnvironmentDetector(ISystemInfoProvider? provider = null)
    {
        _provider = provider ?? new WindowsSystemInfoProvider();
    }

    // ------------------------------------------------------------------
    // Detection
    // ------------------------------------------------------------------

    /// <summary>
    /// Run full environment detection and return results.
    /// </summary>
    public DetectionResult Detect()
    {
        var result = new DetectionResult();

        // Build fingerprint
        result.Fingerprint = BuildFingerprint();

        // Collect all indicators
        result.Indicators.AddRange(DetectOsIndicators());
        result.Indicators.AddRange(DetectSoftwareIndicators());
        result.Indicators.AddRange(DetectServiceIndicators());
        result.Indicators.AddRange(DetectHardwareIndicators());

        // Score each environment type
        result.TypeScores = ScoreEnvironmentTypes(result.Indicators);

        // Select winning type
        var (detectedType, confidence) = SelectType(result.TypeScores);
        result.DetectedType = detectedType;
        result.DetectionConfidence = confidence;
        result.RecommendedProfile = MapToProfile(detectedType);
        result.Summary = BuildSummary(result);
        result.Recommendations = BuildRecommendations(result);

        return result;
    }

    // ------------------------------------------------------------------
    // Fingerprint
    // ------------------------------------------------------------------

    private SystemFingerprint BuildFingerprint()
    {
        var programs = _provider.GetInstalledPrograms();
        var services = _provider.GetRunningServices();

        return new SystemFingerprint
        {
            MachineName = _provider.GetMachineName(),
            OsEdition = _provider.GetOsEdition(),
            OsVersion = _provider.GetOsVersion(),
            IsDomainJoined = _provider.IsDomainJoined(),
            DomainName = _provider.GetDomainName(),
            ProcessorCount = _provider.GetProcessorCount(),
            TotalMemoryMB = _provider.GetTotalMemoryMB(),
            Is64Bit = _provider.Is64BitOs(),
            IsVirtualMachine = _provider.IsVirtualMachine(),
            DetectedSoftwareCategories = ClassifySoftware(programs),
            ActiveServices = services.Take(50).ToList()
        };
    }

    // ------------------------------------------------------------------
    // Indicator collection
    // ------------------------------------------------------------------

    private List<EnvironmentIndicator> DetectOsIndicators()
    {
        var indicators = new List<EnvironmentIndicator>();
        var edition = _provider.GetOsEdition();

        // OS Edition
        if (edition.Contains("Server", StringComparison.OrdinalIgnoreCase))
        {
            indicators.Add(new("OS", "Edition", edition, EnvironmentType.Server, 30));
        }
        else if (edition.Contains("Enterprise", StringComparison.OrdinalIgnoreCase) ||
                 edition.Contains("Education", StringComparison.OrdinalIgnoreCase))
        {
            indicators.Add(new("OS", "Edition", edition, EnvironmentType.Enterprise, 25));
        }
        else if (edition.Contains("Pro", StringComparison.OrdinalIgnoreCase))
        {
            // Pro is ambiguous — could be enterprise or developer
            indicators.Add(new("OS", "Edition", edition, EnvironmentType.Enterprise, 5));
            indicators.Add(new("OS", "Edition", edition, EnvironmentType.Developer, 5));
        }
        else if (edition.Contains("Home", StringComparison.OrdinalIgnoreCase))
        {
            indicators.Add(new("OS", "Edition", edition, EnvironmentType.Home, 20));
        }

        // Domain membership
        if (_provider.IsDomainJoined())
        {
            indicators.Add(new("OS", "DomainJoined", "true", EnvironmentType.Enterprise, 25));
        }
        else
        {
            indicators.Add(new("OS", "DomainJoined", "false", EnvironmentType.Home, 5));
        }

        return indicators;
    }

    private List<EnvironmentIndicator> DetectSoftwareIndicators()
    {
        var indicators = new List<EnvironmentIndicator>();
        var programs = _provider.GetInstalledPrograms();
        var programsLower = programs.Select(p => p.ToLowerInvariant()).ToList();

        // Developer tools
        var devTools = new (string pattern, int weight)[]
        {
            ("visual studio", 15), ("jetbrains", 12), ("android studio", 10),
            ("docker", 10), ("git", 8), ("node.js", 8), ("python", 7),
            ("wsl", 10), ("postman", 7), ("wireshark", 5), ("vscode", 5),
            ("mingw", 8), ("cmake", 7), ("rust", 7), ("golang", 7),
            ("unity", 5), ("unreal", 5)
        };

        int devScore = 0;
        var devMatches = new List<string>();
        foreach (var (pattern, weight) in devTools)
        {
            if (programsLower.Any(p => p.Contains(pattern)))
            {
                devScore += weight;
                devMatches.Add(pattern);
            }
        }

        if (devScore > 0)
        {
            indicators.Add(new("Software", "DeveloperTools",
                string.Join(", ", devMatches.Take(5)),
                EnvironmentType.Developer,
                Math.Min(devScore, 40)));
        }

        // Gaming software
        var gameTools = new (string pattern, int weight)[]
        {
            ("steam", 15), ("epic games", 12), ("nvidia geforce", 10),
            ("razer", 8), ("discord", 5), ("obs studio", 5),
            ("gog galaxy", 8), ("battle.net", 10), ("ea app", 8),
            ("xbox", 5), ("logitech g hub", 7)
        };

        int gameScore = 0;
        var gameMatches = new List<string>();
        foreach (var (pattern, weight) in gameTools)
        {
            if (programsLower.Any(p => p.Contains(pattern)))
            {
                gameScore += weight;
                gameMatches.Add(pattern);
            }
        }

        if (gameScore > 0)
        {
            indicators.Add(new("Software", "GamingSoftware",
                string.Join(", ", gameMatches.Take(5)),
                EnvironmentType.Gaming,
                Math.Min(gameScore, 35)));
        }

        // Enterprise / management tools
        var enterpriseTools = new (string pattern, int weight)[]
        {
            ("microsoft 365", 10), ("office 365", 10), ("sccm", 15),
            ("intune", 15), ("endpoint", 10), ("citrix", 12),
            ("symantec", 8), ("crowdstrike", 12), ("mcafee", 8),
            ("forticlient", 10), ("zscaler", 12), ("azure", 7),
            ("sophos", 8), ("bitlocker", 5), ("airwatch", 10)
        };

        int entScore = 0;
        var entMatches = new List<string>();
        foreach (var (pattern, weight) in enterpriseTools)
        {
            if (programsLower.Any(p => p.Contains(pattern)))
            {
                entScore += weight;
                entMatches.Add(pattern);
            }
        }

        if (entScore > 0)
        {
            indicators.Add(new("Software", "EnterpriseTools",
                string.Join(", ", entMatches.Take(5)),
                EnvironmentType.Enterprise,
                Math.Min(entScore, 35)));
        }

        return indicators;
    }

    private List<EnvironmentIndicator> DetectServiceIndicators()
    {
        var indicators = new List<EnvironmentIndicator>();
        var services = _provider.GetRunningServices();
        var servicesLower = services.Select(s => s.ToLowerInvariant()).ToList();

        // Server services
        var serverServices = new (string pattern, int weight)[]
        {
            ("w3svc", 15),         // IIS
            ("mssqlserver", 15),   // SQL Server
            ("mysql", 12),         // MySQL
            ("postgresql", 12),    // PostgreSQL
            ("dns", 10),           // DNS Server
            ("dhcpserver", 10),    // DHCP Server
            ("ntds", 20),          // Active Directory
            ("kdc", 15),           // Kerberos
            ("termservice", 8),    // Remote Desktop
            ("smtpsvc", 10),       // SMTP
            ("iisadmin", 12),      // IIS Admin
            ("docker", 5),         // Docker (also developer)
            ("msdtc", 5),          // Distributed Transaction Coordinator
        };

        int srvScore = 0;
        var srvMatches = new List<string>();
        foreach (var (pattern, weight) in serverServices)
        {
            if (servicesLower.Any(s => s.Contains(pattern)))
            {
                srvScore += weight;
                srvMatches.Add(pattern);
            }
        }

        if (srvScore > 0)
        {
            indicators.Add(new("Services", "ServerServices",
                string.Join(", ", srvMatches.Take(5)),
                EnvironmentType.Server,
                Math.Min(srvScore, 40)));
        }

        // Enterprise management services
        var entServices = new (string pattern, int weight)[]
        {
            ("sccm", 12), ("intune", 12), ("gpsvc", 8),    // Group Policy
            ("netlogon", 8), ("lanmanserver", 5),
            ("wuauserv", 3),    // Windows Update (everyone has this, low weight)
        };

        int entSvcScore = 0;
        foreach (var (pattern, weight) in entServices)
        {
            if (servicesLower.Any(s => s.Contains(pattern)))
                entSvcScore += weight;
        }

        if (entSvcScore > 0)
        {
            indicators.Add(new("Services", "EnterpriseServices",
                $"score={entSvcScore}", EnvironmentType.Enterprise,
                Math.Min(entSvcScore, 25)));
        }

        return indicators;
    }

    private List<EnvironmentIndicator> DetectHardwareIndicators()
    {
        var indicators = new List<EnvironmentIndicator>();

        var memoryMB = _provider.GetTotalMemoryMB();
        var cpuCount = _provider.GetProcessorCount();

        // High-end hardware suggests gaming or server
        if (memoryMB >= 32_768) // 32 GB+
        {
            indicators.Add(new("Hardware", "HighMemory",
                $"{memoryMB / 1024} GB", EnvironmentType.Server, 8));
            indicators.Add(new("Hardware", "HighMemory",
                $"{memoryMB / 1024} GB", EnvironmentType.Gaming, 5));
        }
        else if (memoryMB >= 16_384) // 16 GB
        {
            indicators.Add(new("Hardware", "MediumMemory",
                $"{memoryMB / 1024} GB", EnvironmentType.Developer, 5));
        }
        else if (memoryMB > 0 && memoryMB < 8_192) // < 8 GB
        {
            indicators.Add(new("Hardware", "LowMemory",
                $"{memoryMB / 1024} GB", EnvironmentType.Home, 5));
        }

        if (cpuCount >= 16)
        {
            indicators.Add(new("Hardware", "HighCPU",
                $"{cpuCount} cores", EnvironmentType.Server, 5));
        }

        // VM detection
        if (_provider.IsVirtualMachine())
        {
            indicators.Add(new("Hardware", "VirtualMachine",
                "true", EnvironmentType.Server, 10));
            indicators.Add(new("Hardware", "VirtualMachine",
                "true", EnvironmentType.Developer, 5));
        }

        return indicators;
    }

    // ------------------------------------------------------------------
    // Scoring & Selection
    // ------------------------------------------------------------------

    private static Dictionary<EnvironmentType, int> ScoreEnvironmentTypes(
        List<EnvironmentIndicator> indicators)
    {
        var scores = new Dictionary<EnvironmentType, int>
        {
            [EnvironmentType.Home] = 10,       // slight default bias
            [EnvironmentType.Developer] = 0,
            [EnvironmentType.Enterprise] = 0,
            [EnvironmentType.Server] = 0,
            [EnvironmentType.Gaming] = 0,
        };

        foreach (var ind in indicators)
        {
            if (scores.ContainsKey(ind.SuggestsType))
                scores[ind.SuggestsType] += ind.Weight;
        }

        return scores;
    }

    private static (EnvironmentType type, Confidence confidence) SelectType(
        Dictionary<EnvironmentType, int> scores)
    {
        if (scores.Count == 0)
            return (EnvironmentType.Unknown, Confidence.Low);

        var sorted = scores.OrderByDescending(kv => kv.Value).ToList();
        var top = sorted[0];
        var second = sorted.Count > 1 ? sorted[1] : default;

        // Confidence based on margin
        Confidence confidence;
        int margin = top.Value - second.Value;

        if (top.Value < 10)
            confidence = Confidence.Low;
        else if (margin >= 20)
            confidence = Confidence.High;
        else if (margin >= 10)
            confidence = Confidence.Medium;
        else
            confidence = Confidence.Low;

        return (top.Key, confidence);
    }

    // ------------------------------------------------------------------
    // Profile mapping
    // ------------------------------------------------------------------

    internal static string MapToProfile(EnvironmentType type) => type switch
    {
        EnvironmentType.Home => "home",
        EnvironmentType.Developer => "developer",
        EnvironmentType.Enterprise => "enterprise",
        EnvironmentType.Server => "server",
        EnvironmentType.Gaming => "home",       // Gaming PCs use home profile with gaming-specific tips
        _ => "home"
    };

    // ------------------------------------------------------------------
    // Summary & Recommendations
    // ------------------------------------------------------------------

    private static string BuildSummary(DetectionResult result)
    {
        var fp = result.Fingerprint;
        var lines = new List<string>
        {
            $"Environment: {result.DetectedType} (confidence: {result.DetectionConfidence})",
            $"Recommended Profile: {result.RecommendedProfile}",
            $"Machine: {fp.MachineName} | OS: {fp.OsEdition} ({fp.OsVersion})",
            $"CPU: {fp.ProcessorCount} cores | RAM: {fp.TotalMemoryMB / 1024} GB | 64-bit: {fp.Is64Bit}",
        };

        if (fp.IsDomainJoined)
            lines.Add($"Domain: {fp.DomainName}");

        if (fp.IsVirtualMachine)
            lines.Add("Running in virtual machine");

        if (fp.DetectedSoftwareCategories.Count > 0)
            lines.Add($"Software: {string.Join(", ", fp.DetectedSoftwareCategories)}");

        lines.Add($"Indicators: {result.Indicators.Count} signals analyzed");

        return string.Join(Environment.NewLine, lines);
    }

    private static List<string> BuildRecommendations(DetectionResult result)
    {
        var recs = new List<string>();

        switch (result.DetectedType)
        {
            case EnvironmentType.Home:
                recs.Add("Run audits with the 'home' profile — it adjusts severity for personal use.");
                recs.Add("Focus on Windows Defender, firewall, and Windows Update findings.");
                recs.Add("Consider enabling BitLocker if your edition supports it.");
                break;

            case EnvironmentType.Developer:
                recs.Add("Run audits with the 'developer' profile — it understands dev tool exceptions.");
                recs.Add("Review network audit findings — dev servers may expose ports.");
                recs.Add("Ensure Docker and WSL configurations are secure.");
                recs.Add("Consider enabling Credential Guard if available.");
                break;

            case EnvironmentType.Enterprise:
                recs.Add("Run audits with the 'enterprise' profile for maximum security coverage.");
                recs.Add("All audit modules are important — don't ignore any category.");
                recs.Add("Coordinate with your IT team for Group Policy and domain-level fixes.");
                recs.Add("Enable all available Windows security features (Credential Guard, ASR, etc.).");
                break;

            case EnvironmentType.Server:
                recs.Add("Run audits with the 'server' profile — strictest security requirements.");
                recs.Add("Minimize attack surface: disable unnecessary services and features.");
                recs.Add("Ensure comprehensive logging and event forwarding.");
                recs.Add("Review network exposure — all open ports should be intentional.");
                recs.Add("Consider Server Core installation to reduce attack surface.");
                break;

            case EnvironmentType.Gaming:
                recs.Add("Run audits with the 'home' profile — most gaming security needs match home users.");
                recs.Add("Review browser security — gaming PCs often have multiple browsers.");
                recs.Add("Ensure game launchers (Steam, Epic, etc.) have 2FA enabled.");
                recs.Add("Monitor startup items — game launchers often add unnecessary startup entries.");
                break;
        }

        if (result.DetectionConfidence == Confidence.Low)
        {
            recs.Add("Detection confidence is low — consider manually selecting a profile with --profile.");
        }

        return recs;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static List<string> ClassifySoftware(IReadOnlyList<string> programs)
    {
        var categories = new HashSet<string>();
        var lower = programs.Select(p => p.ToLowerInvariant()).ToList();

        if (lower.Any(p => p.Contains("visual studio") || p.Contains("jetbrains") ||
                          p.Contains("vscode") || p.Contains("android studio")))
            categories.Add("Development IDEs");

        if (lower.Any(p => p.Contains("docker") || p.Contains("kubernetes") ||
                          p.Contains("vagrant")))
            categories.Add("Containers/Virtualization");

        if (lower.Any(p => p.Contains("git") || p.Contains("node.js") ||
                          p.Contains("python") || p.Contains("java")))
            categories.Add("Dev Runtimes/Tools");

        if (lower.Any(p => p.Contains("steam") || p.Contains("epic games") ||
                          p.Contains("battle.net") || p.Contains("gog")))
            categories.Add("Gaming Platforms");

        if (lower.Any(p => p.Contains("office") || p.Contains("teams") ||
                          p.Contains("slack") || p.Contains("zoom")))
            categories.Add("Productivity/Communication");

        if (lower.Any(p => p.Contains("photoshop") || p.Contains("illustrator") ||
                          p.Contains("premiere") || p.Contains("davinci")))
            categories.Add("Creative/Media");

        if (lower.Any(p => p.Contains("crowdstrike") || p.Contains("symantec") ||
                          p.Contains("sophos") || p.Contains("mcafee")))
            categories.Add("Enterprise Security");

        return categories.OrderBy(c => c).ToList();
    }
}
