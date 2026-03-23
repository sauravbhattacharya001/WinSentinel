using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes and reports security coverage across system domains.
/// Maps audit modules against a comprehensive set of security areas
/// to identify blind spots and coverage gaps. Helps users understand
/// what IS being checked and what is NOT.
/// </summary>
public class SecurityCoverageService
{
    /// <summary>A defined security domain with expected coverage.</summary>
    public record SecurityDomain(
        string Name,
        string Description,
        string[] ExpectedModules,
        string[] ExpectedCategories);

    /// <summary>Coverage result for a single domain.</summary>
    public record DomainCoverage(
        string Domain,
        string Description,
        int TotalChecks,
        int PassingChecks,
        int FailingChecks,
        double CoveragePercent,
        string[] CoveredBy,
        bool HasGap,
        string? GapReason);

    /// <summary>Overall coverage report.</summary>
    public record CoverageReport(
        DateTimeOffset GeneratedAt,
        int TotalDomains,
        int CoveredDomains,
        int GapDomains,
        double OverallCoveragePercent,
        List<DomainCoverage> Domains,
        List<string> Recommendations);

    /// <summary>
    /// Comprehensive list of security domains a Windows system should have covered.
    /// </summary>
    private static readonly SecurityDomain[] AllDomains =
    [
        new("Firewall", "Network firewall rules and configuration",
            ["FirewallAudit"], ["Firewall"]),
        new("Windows Updates", "OS and software patch status",
            ["UpdateAudit"], ["Updates"]),
        new("Antivirus / Defender", "Real-time threat protection",
            ["DefenderAudit"], ["Defender"]),
        new("User Accounts", "Account policies, lockout, and password settings",
            ["AccountAudit"], ["Accounts"]),
        new("Network Security", "Network interfaces, sharing, and protocols",
            ["NetworkAudit"], ["Network"]),
        new("Process Security", "Running processes and suspicious activity",
            ["ProcessAudit"], ["Processes"]),
        new("Startup Programs", "Boot-time and login programs",
            ["StartupAudit"], ["Startup"]),
        new("System Configuration", "Core OS security settings",
            ["SystemAudit"], ["System"]),
        new("Privacy", "Telemetry, tracking, and data collection",
            ["PrivacyAudit"], ["Privacy"]),
        new("Browser Security", "Web browser security settings",
            ["BrowserAudit"], ["Browser"]),
        new("Application Security", "Installed app security posture",
            ["AppSecurityAudit"], ["Applications"]),
        new("Encryption", "Disk encryption and data protection",
            ["EncryptionAudit"], ["Encryption"]),
        new("Event Logging", "Audit log configuration and retention",
            ["EventLogAudit"], ["EventLog"]),
        new("Software Inventory", "Installed software and version tracking",
            ["SoftwareInventoryAudit"], ["Software"]),
        new("Certificates", "Certificate store and trust chain",
            ["CertificateAudit"], ["Certificates"]),
        new("PowerShell Security", "Script execution policy and logging",
            ["PowerShellAudit"], ["PowerShell"]),
        new("DNS Security", "DNS resolver and cache configuration",
            ["DnsAudit"], ["DNS"]),
        new("Scheduled Tasks", "Task scheduler security review",
            ["ScheduledTaskAudit"], ["Tasks"]),
        new("Windows Services", "Service configuration and permissions",
            ["ServiceAudit"], ["Services"]),
        new("Registry Security", "Registry key permissions and settings",
            ["RegistryAudit"], ["Registry"]),
        // Domains with no dedicated module (gaps by design)
        new("Backup & Recovery", "Backup strategy and disaster recovery",
            ["BackupAudit"], ["Backup"]),
        new("Physical Security", "BIOS/UEFI, Secure Boot, TPM",
            [], []),
        new("Email Security", "Email client and phishing protection",
            [], []),
        new("VPN / Remote Access", "VPN and remote desktop security",
            ["RemoteAccessAudit"], ["RemoteAccess"]),
        new("Bluetooth", "Bluetooth adapter and pairing security",
            ["BluetoothAudit"], ["Bluetooth"]),
        new("Wi-Fi Security", "Wireless network security",
            ["WifiAudit"], ["WiFi"]),
        new("Credential Storage", "Password managers and credential vaults",
            ["CredentialExposureAudit"], ["Credentials"]),
        new("Virtualization", "Hyper-V, WSL, and container isolation",
            ["VirtualizationAudit"], ["Virtualization"]),
        new("SMB / File Sharing", "SMB protocol and shared folder security",
            ["SmbShareAudit"], ["SMB"]),
        new("Group Policy", "GPO enforcement and drift",
            ["GroupPolicyAudit"], ["GroupPolicy"]),
        new("Driver Security", "Kernel drivers and signing",
            ["DriverAudit"], ["Drivers"]),
    ];

    /// <summary>
    /// Analyze security coverage from audit report results.
    /// </summary>
    public CoverageReport Analyze(SecurityReport report)
    {
        var moduleNames = report.Results.Select(r => r.ModuleName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var categories = report.Results.Select(r => r.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var domains = new List<DomainCoverage>();
        int covered = 0;

        foreach (var domain in AllDomains)
        {
            var matchingModules = domain.ExpectedModules
                .Where(m => moduleNames.Contains(m))
                .ToArray();

            var matchingCategories = domain.ExpectedCategories
                .Where(c => categories.Any(rc => rc.Contains(c, StringComparison.OrdinalIgnoreCase)))
                .ToArray();

            var coveredByModules = matchingModules.Concat(matchingCategories).Distinct().ToArray();
            bool isCovered = coveredByModules.Length > 0 || domain.ExpectedModules.Length == 0 && domain.ExpectedCategories.Length == 0;

            // If covered, count findings in those modules
            int totalChecks = 0, passing = 0, failing = 0;
            if (isCovered && coveredByModules.Length > 0)
            {
                var relevantResults = report.Results
                    .Where(r => domain.ExpectedModules.Contains(r.ModuleName, StringComparer.OrdinalIgnoreCase) ||
                                domain.ExpectedCategories.Any(c => r.Category.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                totalChecks = relevantResults.Sum(r => r.Findings.Count);
                passing = relevantResults.Sum(r => r.PassCount);
                failing = totalChecks - passing;
            }

            string? gapReason = null;
            bool hasGap;
            if (!isCovered && domain.ExpectedModules.Length > 0)
            {
                hasGap = true;
                gapReason = $"No matching audit module found (expected: {string.Join(", ", domain.ExpectedModules)})";
            }
            else if (domain.ExpectedModules.Length == 0 && domain.ExpectedCategories.Length == 0)
            {
                hasGap = true;
                gapReason = "No audit module exists for this domain";
            }
            else
            {
                hasGap = false;
            }

            double coveragePercent = totalChecks > 0 ? (double)passing / totalChecks * 100 : (isCovered ? 100 : 0);

            if (!hasGap) covered++;

            var coveredByLabels = report.Results
                .Where(r => domain.ExpectedModules.Contains(r.ModuleName, StringComparer.OrdinalIgnoreCase))
                .Select(r => r.ModuleName)
                .Distinct()
                .ToArray();

            domains.Add(new DomainCoverage(
                domain.Name,
                domain.Description,
                totalChecks,
                passing,
                failing,
                Math.Round(coveragePercent, 1),
                coveredByLabels,
                hasGap,
                gapReason));
        }

        double overall = AllDomains.Length > 0 ? (double)covered / AllDomains.Length * 100 : 0;

        var recommendations = new List<string>();
        var gaps = domains.Where(d => d.HasGap).ToList();
        if (gaps.Count > 0)
        {
            recommendations.Add($"{gaps.Count} security domain(s) have no audit coverage");
            foreach (var g in gaps.Take(5))
                recommendations.Add($"  → {g.Domain}: {g.GapReason}");
            if (gaps.Count > 5)
                recommendations.Add($"  → ... and {gaps.Count - 5} more");
        }

        var weakDomains = domains.Where(d => !d.HasGap && d.FailingChecks > d.PassingChecks).ToList();
        if (weakDomains.Count > 0)
        {
            recommendations.Add($"{weakDomains.Count} covered domain(s) have more failures than passes");
            foreach (var w in weakDomains.Take(3))
                recommendations.Add($"  → {w.Domain}: {w.FailingChecks} failing vs {w.PassingChecks} passing");
        }

        if (recommendations.Count == 0)
            recommendations.Add("Coverage looks good! All major domains are being audited.");

        return new CoverageReport(
            DateTimeOffset.UtcNow,
            AllDomains.Length,
            covered,
            gaps.Count,
            Math.Round(overall, 1),
            domains,
            recommendations);
    }
}
