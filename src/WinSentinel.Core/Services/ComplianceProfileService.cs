using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Manages compliance profiles and applies them to security audit reports.
/// Provides 4 built-in profiles (Home, Developer, Enterprise, Server) that
/// customize scoring, severity overrides, and module importance for different environments.
/// </summary>
public class ComplianceProfileService
{
    private readonly Dictionary<string, ComplianceProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);

    public ComplianceProfileService()
    {
        RegisterBuiltInProfiles();
    }

    /// <summary>All registered profile names.</summary>
    public IReadOnlyList<string> ProfileNames => _profiles.Keys.ToList();

    /// <summary>All registered profiles.</summary>
    public IReadOnlyList<ComplianceProfile> Profiles => _profiles.Values.ToList();

    /// <summary>Get a profile by name.</summary>
    public ComplianceProfile? GetProfile(string name) =>
        _profiles.TryGetValue(name, out var profile) ? profile : null;

    /// <summary>Check if a profile exists.</summary>
    public bool ProfileExists(string name) => _profiles.ContainsKey(name);

    /// <summary>
    /// Apply a compliance profile to a security report.
    /// Returns a ComplianceResult with adjusted scores, overrides applied, and compliance verdict.
    /// </summary>
    public ComplianceResult ApplyProfile(string profileName, SecurityReport report)
    {
        var profile = GetProfile(profileName)
            ?? throw new ArgumentException($"Unknown compliance profile: '{profileName}'. Available: {string.Join(", ", _profiles.Keys)}");

        return ApplyProfile(profile, report);
    }

    /// <summary>
    /// Apply a compliance profile to a security report.
    /// </summary>
    public ComplianceResult ApplyProfile(ComplianceProfile profile, SecurityReport report)
    {
        var result = new ComplianceResult
        {
            Profile = profile,
            OriginalScore = report.SecurityScore,
            OriginalGrade = SecurityScorer.GetGrade(report.SecurityScore),
            Recommendations = new List<string>(profile.Recommendations)
        };

        // Track overrides
        var appliedOverrides = new List<AppliedOverride>();
        var moduleScores = new List<ModuleComplianceScore>();

        double totalWeightedScore = 0;
        double totalWeight = 0;
        int modulesSkipped = 0;
        int modulesWeighted = 0;

        foreach (var auditResult in report.Results)
        {
            var category = auditResult.Category;

            // Check if module is skipped
            if (profile.SkippedModules.Contains(category))
            {
                modulesSkipped++;
                moduleScores.Add(new ModuleComplianceScore
                {
                    Category = category,
                    OriginalScore = SecurityScorer.CalculateCategoryScore(auditResult),
                    Weight = 0,
                    Skipped = true,
                    FindingCount = auditResult.Findings.Count
                });
                continue;
            }

            // Apply severity overrides to findings in this module
            int overridesInModule = 0;
            foreach (var finding in auditResult.Findings)
            {
                var matchKey = profile.SeverityOverrides.Keys
                    .FirstOrDefault(k => k.Equals(finding.Title, StringComparison.OrdinalIgnoreCase));

                if (matchKey != null)
                {
                    var ov = profile.SeverityOverrides[matchKey];
                    if (ov.NewSeverity != finding.Severity)
                    {
                        appliedOverrides.Add(new AppliedOverride
                        {
                            FindingTitle = finding.Title,
                            OriginalSeverity = finding.Severity,
                            NewSeverity = ov.NewSeverity,
                            Reason = ov.Reason,
                            ModuleCategory = category
                        });
                        overridesInModule++;
                    }
                }
            }

            // Calculate module score with overrides applied
            int moduleScore = CalculateModuleScoreWithOverrides(auditResult, profile);

            // Get weight for this module
            double weight = 1.0;
            if (profile.ModuleWeights.TryGetValue(category, out double w))
            {
                weight = w;
                if (Math.Abs(weight - 1.0) > 0.001)
                    modulesWeighted++;
            }

            totalWeightedScore += moduleScore * weight;
            totalWeight += weight;

            moduleScores.Add(new ModuleComplianceScore
            {
                Category = category,
                OriginalScore = SecurityScorer.CalculateCategoryScore(auditResult),
                Weight = weight,
                Skipped = false,
                FindingCount = auditResult.Findings.Count,
                OverridesInModule = overridesInModule
            });
        }

        // Calculate adjusted score
        int adjustedScore = totalWeight > 0
            ? (int)Math.Round(totalWeightedScore / totalWeight)
            : 100;
        adjustedScore = Math.Clamp(adjustedScore, 0, 100);

        result.AdjustedScore = adjustedScore;
        result.AdjustedGrade = SecurityScorer.GetGrade(adjustedScore);
        result.OverridesApplied = appliedOverrides.Count;
        result.ModulesSkipped = modulesSkipped;
        result.ModulesWeighted = modulesWeighted;
        result.ModuleScores = moduleScores;
        result.AppliedOverrides = appliedOverrides;

        // Add compliance-specific recommendations
        if (!result.IsCompliant)
        {
            int deficit = profile.ComplianceThreshold - adjustedScore;
            result.Recommendations.Insert(0,
                $"Score is {deficit} points below the {profile.DisplayName} compliance threshold of {profile.ComplianceThreshold}.");
        }

        return result;
    }

    /// <summary>
    /// Calculate a module's score with severity overrides from a profile applied.
    /// </summary>
    public static int CalculateModuleScoreWithOverrides(AuditResult auditResult, ComplianceProfile profile)
    {
        int deductions = 0;

        foreach (var finding in auditResult.Findings)
        {
            var effectiveSeverity = finding.Severity;

            // Check for override
            var matchKey = profile.SeverityOverrides.Keys
                .FirstOrDefault(k => k.Equals(finding.Title, StringComparison.OrdinalIgnoreCase));

            if (matchKey != null)
            {
                effectiveSeverity = profile.SeverityOverrides[matchKey].NewSeverity;
            }

            deductions += effectiveSeverity switch
            {
                Severity.Critical => 20,
                Severity.Warning => 5,
                _ => 0
            };
        }

        return Math.Max(0, 100 - deductions);
    }

    // ── Built-in Profiles ────────────────────────────────────────────

    private void RegisterBuiltInProfiles()
    {
        _profiles["home"] = CreateHomeProfile();
        _profiles["developer"] = CreateDeveloperProfile();
        _profiles["enterprise"] = CreateEnterpriseProfile();
        _profiles["server"] = CreateServerProfile();
    }

    /// <summary>
    /// Home/Personal Use profile — relaxed settings for personal computers.
    /// Focuses on basic security hygiene, less emphasis on enterprise features.
    /// </summary>
    internal static ComplianceProfile CreateHomeProfile() => new()
    {
        Name = "home",
        DisplayName = "Home / Personal",
        Description = "Relaxed profile for personal computers. Focuses on basic security hygiene — antivirus, firewall, updates. De-emphasizes enterprise-only features like BitLocker, Group Policy, and advanced network controls.",
        TargetAudience = "Home users, personal laptops, family computers",
        ComplianceThreshold = 60,
        ModuleWeights = new Dictionary<string, double>
        {
            ["Firewall & Network Protection"] = 1.0,
            ["Windows Updates"] = 1.2,       // Updates are critical for home users
            ["Windows Defender"] = 1.2,       // Antivirus is key
            ["Account Security"] = 1.0,
            ["Network Configuration"] = 0.7,  // Less important for home
            ["Running Processes"] = 0.5,       // Less relevant
            ["Startup Programs"] = 0.8,
            ["System Configuration"] = 0.6,
            ["Privacy & Telemetry"] = 1.0,     // Home users care about privacy
            ["Browser Security"] = 1.0,
            ["Application Security"] = 0.7,
            ["Encryption"] = 0.5,              // BitLocker less common at home
            ["Event Log"] = 0.3,               // Not relevant for most home users
        },
        SeverityOverrides = new Dictionary<string, SeverityOverride>
        {
            ["SMB Signing Not Required"] = new(Severity.Info, "SMB signing is an enterprise network concern, not critical for home use"),
            ["LLMNR Protocol Enabled"] = new(Severity.Info, "LLMNR poisoning requires local network attacker — low risk on home networks"),
            ["NetBIOS over TCP/IP Enabled"] = new(Severity.Info, "NetBIOS is common on home networks for device discovery"),
            ["Audit Policy Not Configured"] = new(Severity.Info, "Detailed audit logging is an enterprise requirement"),
            ["No Password Expiration Policy"] = new(Severity.Info, "Password expiration is no longer recommended even by NIST for home use"),
            ["Guest Account Status"] = new(Severity.Info, "Guest account on a personal machine is typically not a risk"),
        },
        Recommendations =
        [
            "Keep Windows and all software updated automatically",
            "Use Windows Defender — it's built-in and effective",
            "Enable Windows Firewall on all network profiles",
            "Use strong, unique passwords with a password manager",
            "Be cautious with email attachments and downloads",
        ]
    };

    /// <summary>
    /// Developer Workstation profile — balanced for development work.
    /// Acknowledges that developers need some relaxed settings (local servers, debugging ports)
    /// while still maintaining good security practices.
    /// </summary>
    internal static ComplianceProfile CreateDeveloperProfile() => new()
    {
        Name = "developer",
        DisplayName = "Developer Workstation",
        Description = "Balanced profile for development machines. Allows common dev practices (local servers, open ports for debugging) while maintaining core security. Emphasizes code-relevant security like encryption and browser hardening.",
        TargetAudience = "Software developers, DevOps engineers, IT professionals",
        ComplianceThreshold = 70,
        ModuleWeights = new Dictionary<string, double>
        {
            ["Firewall & Network Protection"] = 0.9,  // Devs often need custom rules
            ["Windows Updates"] = 1.0,
            ["Windows Defender"] = 1.0,
            ["Account Security"] = 1.0,
            ["Network Configuration"] = 0.8,
            ["Running Processes"] = 0.6,       // Devs run many processes
            ["Startup Programs"] = 0.7,        // IDEs, Docker, etc. at startup
            ["System Configuration"] = 0.8,
            ["Privacy & Telemetry"] = 1.0,
            ["Browser Security"] = 1.2,        // Devs browse a lot of sites
            ["Application Security"] = 1.0,
            ["Encryption"] = 1.2,              // Protect source code and secrets
            ["Event Log"] = 0.5,
        },
        SeverityOverrides = new Dictionary<string, SeverityOverride>
        {
            ["SMB Signing Not Required"] = new(Severity.Info, "Less relevant on isolated dev machines"),
            ["Multiple Listening Services"] = new(Severity.Info, "Development servers (webpack, node, docker) are expected"),
            ["Audit Policy Not Configured"] = new(Severity.Info, "Detailed audit logging is optional for dev machines"),
            ["No Password Expiration Policy"] = new(Severity.Info, "Not required for individual dev workstations"),
        },
        Recommendations =
        [
            "Enable full disk encryption to protect source code and credentials",
            "Use SSH keys instead of passwords for Git operations",
            "Keep development tools and dependencies updated",
            "Use environment variables or secret managers — never commit credentials",
            "Enable browser security features to protect against supply chain attacks",
            "Review startup programs periodically — dev tools accumulate over time",
        ]
    };

    /// <summary>
    /// Enterprise/Corporate profile — strict settings for business workstations.
    /// Enforces compliance with common enterprise security standards.
    /// All modules are important; some findings are elevated to Critical.
    /// </summary>
    internal static ComplianceProfile CreateEnterpriseProfile() => new()
    {
        Name = "enterprise",
        DisplayName = "Enterprise / Corporate",
        Description = "Strict profile for corporate workstations. Enforces enterprise security standards — all modules weighted heavily, encryption required, audit logging mandatory, network hardening enforced. Suitable for SOC 2, ISO 27001, and general corporate compliance.",
        TargetAudience = "Corporate workstations, managed endpoints, compliance-regulated environments",
        ComplianceThreshold = 85,
        ModuleWeights = new Dictionary<string, double>
        {
            ["Firewall & Network Protection"] = 1.3,
            ["Windows Updates"] = 1.3,
            ["Windows Defender"] = 1.2,
            ["Account Security"] = 1.3,
            ["Network Configuration"] = 1.2,
            ["Running Processes"] = 1.0,
            ["Startup Programs"] = 1.0,
            ["System Configuration"] = 1.0,
            ["Privacy & Telemetry"] = 0.8,     // Less priority than security
            ["Browser Security"] = 1.0,
            ["Application Security"] = 1.2,
            ["Encryption"] = 1.5,              // Encryption is critical in enterprise
            ["Event Log"] = 1.3,               // Audit logging is mandatory
        },
        SeverityOverrides = new Dictionary<string, SeverityOverride>
        {
            ["SMB Signing Not Required"] = new(Severity.Critical, "SMB signing prevents relay attacks — mandatory in enterprise networks"),
            ["BitLocker Not Enabled"] = new(Severity.Critical, "Full disk encryption is required for corporate data protection"),
            ["Audit Policy Not Configured"] = new(Severity.Critical, "Audit logging is mandatory for compliance and incident response"),
            ["No Password Expiration Policy"] = new(Severity.Warning, "Enterprise password policies should be managed via Group Policy"),
            ["Remote Desktop Enabled"] = new(Severity.Warning, "RDP should be restricted to authorized users with NLA enabled"),
            ["LLMNR Protocol Enabled"] = new(Severity.Critical, "LLMNR poisoning is a common lateral movement technique in corporate networks"),
            ["NetBIOS over TCP/IP Enabled"] = new(Severity.Warning, "NetBIOS should be disabled on enterprise networks to reduce attack surface"),
        },
        Recommendations =
        [
            "Enable BitLocker on all drives with TPM-backed encryption",
            "Configure Group Policy for centralized security management",
            "Enable comprehensive audit logging for compliance",
            "Implement network segmentation and disable legacy protocols",
            "Deploy endpoint detection and response (EDR) solution",
            "Enforce multi-factor authentication for all users",
            "Regularly review and rotate service account credentials",
        ]
    };

    /// <summary>
    /// Server profile — maximum security for server workloads.
    /// Every module is critical. Minimal attack surface expected.
    /// </summary>
    internal static ComplianceProfile CreateServerProfile() => new()
    {
        Name = "server",
        DisplayName = "Server / Infrastructure",
        Description = "Maximum security profile for servers. All modules weighted at maximum importance. Expects minimal attack surface — no unnecessary services, full encryption, comprehensive logging, hardened network configuration. Suitable for production servers, domain controllers, and critical infrastructure.",
        TargetAudience = "Production servers, domain controllers, infrastructure hosts, critical systems",
        ComplianceThreshold = 90,
        ModuleWeights = new Dictionary<string, double>
        {
            ["Firewall & Network Protection"] = 1.5,
            ["Windows Updates"] = 1.5,
            ["Windows Defender"] = 1.3,
            ["Account Security"] = 1.5,
            ["Network Configuration"] = 1.5,
            ["Running Processes"] = 1.3,       // Minimize running services
            ["Startup Programs"] = 1.2,
            ["System Configuration"] = 1.2,
            ["Privacy & Telemetry"] = 0.5,     // Less relevant for servers
            ["Browser Security"] = 0.3,        // Servers shouldn't have browsers
            ["Application Security"] = 1.3,
            ["Encryption"] = 1.5,              // Critical for data at rest
            ["Event Log"] = 1.5,               // SIEM integration mandatory
        },
        SeverityOverrides = new Dictionary<string, SeverityOverride>
        {
            ["SMB Signing Not Required"] = new(Severity.Critical, "SMB signing is mandatory on servers to prevent relay attacks"),
            ["BitLocker Not Enabled"] = new(Severity.Critical, "Server drives must be encrypted"),
            ["Audit Policy Not Configured"] = new(Severity.Critical, "Server audit logging is mandatory for security monitoring"),
            ["LLMNR Protocol Enabled"] = new(Severity.Critical, "LLMNR must be disabled on servers"),
            ["NetBIOS over TCP/IP Enabled"] = new(Severity.Critical, "NetBIOS must be disabled on servers"),
            ["Remote Desktop Enabled"] = new(Severity.Critical, "RDP should be disabled or strictly controlled on servers"),
            ["No Password Expiration Policy"] = new(Severity.Critical, "Server accounts require password policies"),
            ["Guest Account Status"] = new(Severity.Critical, "Guest account must be disabled on servers"),
            ["Multiple Listening Services"] = new(Severity.Warning, "Servers should run minimal services — review for unnecessary listeners"),
        },
        Recommendations =
        [
            "Implement Server Core where possible to minimize attack surface",
            "Enable Windows Defender Credential Guard",
            "Configure Windows Event Forwarding to a central SIEM",
            "Disable all unnecessary services and features",
            "Use Just-In-Time (JIT) and Just-Enough-Administration (JEA)",
            "Implement network microsegmentation",
            "Enable boot integrity with Secure Boot and TPM",
            "Schedule regular vulnerability scans",
        ]
    };
}
