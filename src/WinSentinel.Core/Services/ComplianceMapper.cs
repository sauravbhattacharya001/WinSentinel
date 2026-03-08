using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Maps security audit findings to industry regulatory compliance controls.
/// Supports CIS Benchmarks, NIST 800-53, PCI-DSS, and HIPAA Security Rule.
/// Generates a compliance posture report showing per-control pass/fail/gap status.
/// </summary>
public class ComplianceMapper
{
    private readonly List<ComplianceFramework> _frameworks;

    public ComplianceMapper()
    {
        _frameworks = BuildFrameworks();
    }

    /// <summary>Available compliance framework IDs.</summary>
    public IReadOnlyList<string> FrameworkIds =>
        _frameworks.Select(f => f.Id).ToList();

    /// <summary>Get a framework by ID.</summary>
    public ComplianceFramework? GetFramework(string frameworkId) =>
        _frameworks.FirstOrDefault(f =>
            string.Equals(f.Id, frameworkId, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Evaluate a security report against a specific compliance framework.
    /// Maps each finding's category + title patterns to framework controls.
    /// </summary>
    public ComplianceReport Evaluate(SecurityReport report, string frameworkId)
    {
        var framework = GetFramework(frameworkId)
            ?? throw new ArgumentException(
                $"Unknown framework: '{frameworkId}'. Available: {string.Join(", ", FrameworkIds)}");

        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .ToList();

        var controlResults = new List<ControlResult>();

        foreach (var control in framework.Controls)
        {
            var matchedFindings = allFindings
                .Where(f => MatchesControl(f, control))
                .ToList();

            ControlStatus status;
            if (matchedFindings.Count == 0)
            {
                // No findings matched — could be not assessed or passing by absence
                status = ControlStatus.NotAssessed;
            }
            else if (matchedFindings.All(f => f.Severity == Severity.Pass))
            {
                status = ControlStatus.Pass;
            }
            else if (matchedFindings.Any(f => f.Severity == Severity.Critical))
            {
                status = ControlStatus.Fail;
            }
            else if (matchedFindings.Any(f => f.Severity == Severity.Warning))
            {
                status = ControlStatus.Partial;
            }
            else
            {
                status = ControlStatus.Pass;
            }

            controlResults.Add(new ControlResult
            {
                ControlId = control.Id,
                ControlTitle = control.Title,
                ControlDescription = control.Description,
                Status = status,
                RelatedFindings = matchedFindings,
                Remediation = status == ControlStatus.Fail || status == ControlStatus.Partial
                    ? matchedFindings
                        .Where(f => f.Remediation != null)
                        .Select(f => f.Remediation!)
                        .Distinct()
                        .ToList()
                    : new List<string>()
            });
        }

        var passCount = controlResults.Count(c => c.Status == ControlStatus.Pass);
        var failCount = controlResults.Count(c => c.Status == ControlStatus.Fail);
        var partialCount = controlResults.Count(c => c.Status == ControlStatus.Partial);
        var notAssessedCount = controlResults.Count(c => c.Status == ControlStatus.NotAssessed);
        var assessedCount = passCount + failCount + partialCount;

        return new ComplianceReport
        {
            FrameworkId = framework.Id,
            FrameworkName = framework.Name,
            FrameworkVersion = framework.Version,
            GeneratedAt = DateTimeOffset.UtcNow,
            Controls = controlResults,
            Summary = new ComplianceSummary
            {
                TotalControls = controlResults.Count,
                PassCount = passCount,
                FailCount = failCount,
                PartialCount = partialCount,
                NotAssessedCount = notAssessedCount,
                CompliancePercentage = assessedCount > 0
                    ? Math.Round((double)passCount / assessedCount * 100, 1)
                    : 0,
                OverallVerdict = failCount > 0
                    ? ComplianceVerdict.NonCompliant
                    : partialCount > 0
                        ? ComplianceVerdict.PartiallyCompliant
                        : assessedCount > 0
                            ? ComplianceVerdict.Compliant
                            : ComplianceVerdict.NotAssessed
            }
        };
    }

    /// <summary>
    /// Evaluate a report against all available frameworks.
    /// </summary>
    public List<ComplianceReport> EvaluateAll(SecurityReport report)
    {
        return _frameworks
            .Select(f => Evaluate(report, f.Id))
            .ToList();
    }

    /// <summary>
    /// Get a cross-framework summary showing how a report fares across all frameworks.
    /// </summary>
    public CrossFrameworkSummary CrossFrameworkAnalysis(SecurityReport report)
    {
        var reports = EvaluateAll(report);
        return new CrossFrameworkSummary
        {
            SecurityScore = report.SecurityScore,
            FrameworkResults = reports.Select(r => new FrameworkResult
            {
                FrameworkId = r.FrameworkId,
                FrameworkName = r.FrameworkName,
                CompliancePercentage = r.Summary.CompliancePercentage,
                Verdict = r.Summary.OverallVerdict,
                PassCount = r.Summary.PassCount,
                FailCount = r.Summary.FailCount,
                PartialCount = r.Summary.PartialCount,
                NotAssessedCount = r.Summary.NotAssessedCount,
                CriticalGaps = r.Controls
                    .Where(c => c.Status == ControlStatus.Fail)
                    .Select(c => c.ControlId + ": " + c.ControlTitle)
                    .ToList()
            }).ToList()
        };
    }

    // ── Matching ─────────────────────────────────────────────────────

    private static bool MatchesControl(Finding finding, ComplianceControl control)
    {
        // Match by category
        if (control.Categories.Count > 0 &&
            !control.Categories.Any(c =>
                string.Equals(c, finding.Category, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        // Match by keyword patterns in title or description
        if (control.Keywords.Count > 0)
        {
            var text = (finding.Title + " " + finding.Description).ToLowerInvariant();
            return control.Keywords.Any(kw => text.Contains(kw.ToLowerInvariant()));
        }

        // Category-only match (no keywords = match all findings in those categories)
        return control.Categories.Count > 0;
    }

    // ── Framework Definitions ────────────────────────────────────────

    private static List<ComplianceFramework> BuildFrameworks()
    {
        return new List<ComplianceFramework>
        {
            BuildCisBenchmark(),
            BuildNist80053(),
            BuildPciDss(),
            BuildHipaa()
        };
    }

    private static ComplianceFramework BuildCisBenchmark()
    {
        return new ComplianceFramework
        {
            Id = "cis",
            Name = "CIS Microsoft Windows Benchmarks",
            Version = "3.0.0",
            Controls = new List<ComplianceControl>
            {
                new() { Id = "CIS-1.1", Title = "Password Policy", Description = "Enforce strong password requirements",
                    Categories = { "Accounts" }, Keywords = { "password", "lockout", "complexity" } },
                new() { Id = "CIS-1.2", Title = "Account Lockout Policy", Description = "Configure account lockout thresholds",
                    Categories = { "Accounts" }, Keywords = { "lockout", "threshold", "duration" } },
                new() { Id = "CIS-2.1", Title = "Audit Policy Configuration", Description = "Configure system audit policies",
                    Categories = { "Event Logs" }, Keywords = { "audit", "logging", "event log" } },
                new() { Id = "CIS-2.2", Title = "Security Log Size", Description = "Ensure adequate security log retention",
                    Categories = { "Event Logs" }, Keywords = { "log size", "retention", "maximum" } },
                new() { Id = "CIS-5.1", Title = "Windows Firewall - Domain Profile", Description = "Enable firewall for domain profile",
                    Categories = { "Firewall" }, Keywords = { "firewall", "enabled", "domain" } },
                new() { Id = "CIS-5.2", Title = "Windows Firewall - Private Profile", Description = "Enable firewall for private profile",
                    Categories = { "Firewall" }, Keywords = { "firewall", "enabled", "private" } },
                new() { Id = "CIS-5.3", Title = "Windows Firewall - Public Profile", Description = "Enable firewall for public profile",
                    Categories = { "Firewall" }, Keywords = { "firewall", "enabled", "public" } },
                new() { Id = "CIS-9.1", Title = "Windows Defender Configuration", Description = "Ensure real-time protection is enabled",
                    Categories = { "Defender" }, Keywords = { "defender", "real-time", "protection", "antivirus" } },
                new() { Id = "CIS-9.2", Title = "Windows Defender Updates", Description = "Ensure definitions are up to date",
                    Categories = { "Defender" }, Keywords = { "definition", "update", "signature" } },
                new() { Id = "CIS-17.1", Title = "User Rights Assignment", Description = "Restrict privileged user rights",
                    Categories = { "Accounts", "GroupPolicy" }, Keywords = { "privilege", "admin", "right", "elevated" } },
                new() { Id = "CIS-18.1", Title = "BitLocker Drive Encryption", Description = "Configure drive encryption",
                    Categories = { "Encryption" }, Keywords = { "bitlocker", "encrypt", "drive" } },
                new() { Id = "CIS-18.2", Title = "Remote Desktop Services", Description = "Secure Remote Desktop configuration",
                    Categories = { "Remote Access" }, Keywords = { "remote desktop", "rdp", "terminal" } },
                new() { Id = "CIS-18.3", Title = "Windows Update Configuration", Description = "Configure automatic updates",
                    Categories = { "Updates" }, Keywords = { "update", "patch", "wsus", "automatic" } },
            }
        };
    }

    private static ComplianceFramework BuildNist80053()
    {
        return new ComplianceFramework
        {
            Id = "nist",
            Name = "NIST SP 800-53 Rev. 5",
            Version = "Rev. 5",
            Controls = new List<ComplianceControl>
            {
                new() { Id = "AC-2", Title = "Account Management", Description = "Manage system accounts, group memberships, and access",
                    Categories = { "Accounts" }, Keywords = { "account", "user", "group", "privilege", "admin" } },
                new() { Id = "AC-3", Title = "Access Enforcement", Description = "Enforce approved authorizations for access",
                    Categories = { "Accounts", "GroupPolicy" }, Keywords = { "access", "permission", "authorization", "enforce" } },
                new() { Id = "AC-7", Title = "Unsuccessful Logon Attempts", Description = "Limit consecutive invalid logon attempts",
                    Categories = { "Accounts" }, Keywords = { "lockout", "logon", "failed", "attempt" } },
                new() { Id = "AC-17", Title = "Remote Access", Description = "Establish usage restrictions for remote access",
                    Categories = { "Remote Access" }, Keywords = { "remote", "rdp", "ssh", "vpn" } },
                new() { Id = "AU-2", Title = "Event Logging", Description = "Identify events that need to be logged",
                    Categories = { "Event Logs" }, Keywords = { "audit", "log", "event", "monitoring" } },
                new() { Id = "AU-6", Title = "Audit Record Review", Description = "Review and analyze audit records",
                    Categories = { "Event Logs" }, Keywords = { "review", "analysis", "log", "audit" } },
                new() { Id = "CA-7", Title = "Continuous Monitoring", Description = "Implement continuous monitoring strategy",
                    Categories = { "Defender", "Processes" }, Keywords = { "monitor", "continuous", "real-time", "scan" } },
                new() { Id = "CM-6", Title = "Configuration Settings", Description = "Establish mandatory configuration settings",
                    Categories = { "Registry", "GroupPolicy", "System" }, Keywords = { "configuration", "setting", "policy", "registry" } },
                new() { Id = "CM-7", Title = "Least Functionality", Description = "Configure system to provide only essential capabilities",
                    Categories = { "Services", "Startup" }, Keywords = { "service", "startup", "unnecessary", "disable" } },
                new() { Id = "IA-5", Title = "Authenticator Management", Description = "Manage system authenticators (passwords, certificates)",
                    Categories = { "Accounts", "Certificates", "Credentials" }, Keywords = { "password", "certificate", "credential", "authentication" } },
                new() { Id = "SC-7", Title = "Boundary Protection", Description = "Monitor and control communications at system boundary",
                    Categories = { "Firewall", "Network" }, Keywords = { "firewall", "boundary", "network", "port", "traffic" } },
                new() { Id = "SC-12", Title = "Cryptographic Key Management", Description = "Establish and manage cryptographic keys",
                    Categories = { "Encryption", "Certificates" }, Keywords = { "key", "certificate", "crypto", "tls", "ssl", "encrypt" } },
                new() { Id = "SC-28", Title = "Protection of Information at Rest", Description = "Protect information at rest",
                    Categories = { "Encryption" }, Keywords = { "encrypt", "bitlocker", "at rest", "drive" } },
                new() { Id = "SI-2", Title = "Flaw Remediation", Description = "Identify and correct system flaws",
                    Categories = { "Updates", "Software" }, Keywords = { "update", "patch", "vulnerability", "remediat" } },
                new() { Id = "SI-3", Title = "Malicious Code Protection", Description = "Protect against malicious code",
                    Categories = { "Defender" }, Keywords = { "malware", "antivirus", "defender", "protection" } },
                new() { Id = "SI-4", Title = "System Monitoring", Description = "Monitor the system to detect attacks",
                    Categories = { "Event Logs", "Defender", "Processes" }, Keywords = { "monitor", "detect", "alert", "anomal" } },
            }
        };
    }

    private static ComplianceFramework BuildPciDss()
    {
        return new ComplianceFramework
        {
            Id = "pci-dss",
            Name = "PCI DSS v4.0",
            Version = "4.0",
            Controls = new List<ComplianceControl>
            {
                new() { Id = "PCI-1.1", Title = "Network Security Controls", Description = "Install and maintain network security controls",
                    Categories = { "Firewall", "Network" }, Keywords = { "firewall", "network", "rule", "port" } },
                new() { Id = "PCI-2.1", Title = "Secure Configurations", Description = "Apply secure configurations to all system components",
                    Categories = { "System", "Registry", "Services" }, Keywords = { "configuration", "default", "harden", "secure" } },
                new() { Id = "PCI-3.1", Title = "Data Protection", Description = "Protect stored account data",
                    Categories = { "Encryption", "Credentials" }, Keywords = { "encrypt", "data", "protect", "credential", "store" } },
                new() { Id = "PCI-5.1", Title = "Anti-Malware", Description = "Protect all systems against malware",
                    Categories = { "Defender" }, Keywords = { "antivirus", "malware", "defender", "protection", "scan" } },
                new() { Id = "PCI-5.2", Title = "Anti-Malware Updates", Description = "Ensure anti-malware mechanisms are current",
                    Categories = { "Defender" }, Keywords = { "definition", "update", "signature", "current" } },
                new() { Id = "PCI-6.1", Title = "Security Patches", Description = "Identify and address vulnerabilities",
                    Categories = { "Updates", "Software" }, Keywords = { "patch", "update", "vulnerability", "version" } },
                new() { Id = "PCI-7.1", Title = "Access Control", Description = "Restrict access to system components by business need",
                    Categories = { "Accounts" }, Keywords = { "access", "privilege", "admin", "restrict", "least" } },
                new() { Id = "PCI-8.1", Title = "User Authentication", Description = "Identify users and authenticate access",
                    Categories = { "Accounts" }, Keywords = { "password", "authentication", "identity", "logon" } },
                new() { Id = "PCI-10.1", Title = "Logging and Monitoring", Description = "Log and monitor all access to system components",
                    Categories = { "Event Logs" }, Keywords = { "log", "audit", "monitor", "track", "event" } },
                new() { Id = "PCI-11.1", Title = "Security Testing", Description = "Test security of systems and networks regularly",
                    Categories = { "Network", "WiFi" }, Keywords = { "test", "scan", "wireless", "rogue" } },
                new() { Id = "PCI-12.1", Title = "Security Policy", Description = "Support information security with organizational policies",
                    Categories = { "GroupPolicy" }, Keywords = { "policy", "security", "organization" } },
            }
        };
    }

    private static ComplianceFramework BuildHipaa()
    {
        return new ComplianceFramework
        {
            Id = "hipaa",
            Name = "HIPAA Security Rule",
            Version = "45 CFR Part 164",
            Controls = new List<ComplianceControl>
            {
                new() { Id = "164.308(a)(1)", Title = "Security Management Process", Description = "Implement policies to prevent, detect, contain security violations",
                    Categories = { "Defender", "Event Logs" }, Keywords = { "security", "policy", "monitor", "detect" } },
                new() { Id = "164.308(a)(3)", Title = "Workforce Security", Description = "Ensure appropriate access to ePHI",
                    Categories = { "Accounts" }, Keywords = { "access", "user", "account", "privilege", "authorization" } },
                new() { Id = "164.308(a)(4)", Title = "Information Access Management", Description = "Authorize access to ePHI",
                    Categories = { "Accounts", "GroupPolicy" }, Keywords = { "access", "authorization", "permission", "role" } },
                new() { Id = "164.308(a)(5)", Title = "Security Awareness and Training", Description = "Implement security awareness program",
                    Categories = { "Accounts" }, Keywords = { "password", "awareness", "training", "phish" } },
                new() { Id = "164.310(a)(1)", Title = "Facility Access Controls", Description = "Limit physical access to electronic information systems",
                    Categories = { "System", "Encryption" }, Keywords = { "physical", "lock", "access", "facility" } },
                new() { Id = "164.310(d)(1)", Title = "Device and Media Controls", Description = "Govern receipt and removal of hardware and media",
                    Categories = { "Encryption", "Drivers" }, Keywords = { "device", "media", "removable", "usb", "drive", "encrypt" } },
                new() { Id = "164.312(a)(1)", Title = "Access Control", Description = "Allow access only to authorized persons or software",
                    Categories = { "Accounts", "Remote Access" }, Keywords = { "access", "control", "login", "authenticate", "remote" } },
                new() { Id = "164.312(b)", Title = "Audit Controls", Description = "Record and examine activity in information systems",
                    Categories = { "Event Logs" }, Keywords = { "audit", "log", "record", "examine", "trail" } },
                new() { Id = "164.312(c)(1)", Title = "Integrity Controls", Description = "Protect ePHI from improper alteration or destruction",
                    Categories = { "Encryption", "Backup" }, Keywords = { "integrity", "backup", "alter", "protect" } },
                new() { Id = "164.312(d)", Title = "Person or Entity Authentication", Description = "Verify identity of persons seeking access",
                    Categories = { "Accounts", "Certificates" }, Keywords = { "authentication", "verify", "identity", "certificate" } },
                new() { Id = "164.312(e)(1)", Title = "Transmission Security", Description = "Guard against unauthorized access to ePHI during transmission",
                    Categories = { "Network", "Encryption", "WiFi" }, Keywords = { "transmit", "encrypt", "tls", "ssl", "network", "wifi" } },
            }
        };
    }
}

// ── Models ─────────────────────────────────────────────────────────

public class ComplianceFramework
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public List<ComplianceControl> Controls { get; set; } = new();
}

public class ComplianceControl
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>Audit categories this control maps to (e.g., "Accounts", "Firewall").</summary>
    public List<string> Categories { get; set; } = new();
    /// <summary>Keywords to match in finding title/description.</summary>
    public List<string> Keywords { get; set; } = new();
}

public enum ControlStatus
{
    Pass,
    Fail,
    Partial,
    NotAssessed
}

public enum ComplianceVerdict
{
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotAssessed
}

public class ControlResult
{
    public string ControlId { get; set; } = "";
    public string ControlTitle { get; set; } = "";
    public string ControlDescription { get; set; } = "";
    public ControlStatus Status { get; set; }
    public List<Finding> RelatedFindings { get; set; } = new();
    public List<string> Remediation { get; set; } = new();
}

public class ComplianceSummary
{
    public int TotalControls { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public int PartialCount { get; set; }
    public int NotAssessedCount { get; set; }
    /// <summary>Pass / (Pass + Fail + Partial) * 100.</summary>
    public double CompliancePercentage { get; set; }
    public ComplianceVerdict OverallVerdict { get; set; }
}

public class ComplianceReport
{
    public string FrameworkId { get; set; } = "";
    public string FrameworkName { get; set; } = "";
    public string FrameworkVersion { get; set; } = "";
    public DateTimeOffset GeneratedAt { get; set; }
    public List<ControlResult> Controls { get; set; } = new();
    public ComplianceSummary Summary { get; set; } = new();
}

public class CrossFrameworkSummary
{
    public int SecurityScore { get; set; }
    public List<FrameworkResult> FrameworkResults { get; set; } = new();
}

public class FrameworkResult
{
    public string FrameworkId { get; set; } = "";
    public string FrameworkName { get; set; } = "";
    public double CompliancePercentage { get; set; }
    public ComplianceVerdict Verdict { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public int PartialCount { get; set; }
    public int NotAssessedCount { get; set; }
    public List<string> CriticalGaps { get; set; } = new();
}
