using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Evaluates security maturity across domains based on audit findings.
/// Uses a CMMI-inspired 1–5 scale per domain and computes an overall grade.
/// </summary>
public sealed class MaturityAssessmentService
{
    // Map audit categories → maturity domains
    private static readonly Dictionary<string, string> CategoryToDomain = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Accounts"] = "Identity & Access",
        ["Credentials"] = "Identity & Access",
        ["Remote Access"] = "Identity & Access",
        ["Firewall"] = "Network Security",
        ["Network"] = "Network Security",
        ["DNS"] = "Network Security",
        ["WiFi"] = "Network Security",
        ["SMB"] = "Network Security",
        ["Bluetooth"] = "Network Security",
        ["Defender"] = "Endpoint Protection",
        ["Processes"] = "Endpoint Protection",
        ["Drivers"] = "Endpoint Protection",
        ["Services"] = "Endpoint Protection",
        ["Startup"] = "Endpoint Protection",
        ["Encryption"] = "Data Protection",
        ["Privacy"] = "Data Protection",
        ["Browser"] = "Data Protection",
        ["Certificates"] = "Data Protection",
        ["Updates"] = "Patch & Config Management",
        ["Applications"] = "Patch & Config Management",
        ["Software"] = "Patch & Config Management",
        ["Registry"] = "Patch & Config Management",
        ["GroupPolicy"] = "Patch & Config Management",
        ["System"] = "System Hardening",
        ["Environment"] = "System Hardening",
        ["PowerShell"] = "System Hardening",
        ["Virtualization"] = "System Hardening",
        ["Backup"] = "Resilience & Recovery",
        ["Event Logs"] = "Resilience & Recovery",
        ["ScheduledTasks"] = "Resilience & Recovery",
    };

    private static readonly Dictionary<string, string> DomainDescriptions = new()
    {
        ["Identity & Access"] = "User accounts, credentials, and remote access controls",
        ["Network Security"] = "Firewall, network configuration, DNS, Wi-Fi, and Bluetooth",
        ["Endpoint Protection"] = "Antivirus, process monitoring, drivers, and services",
        ["Data Protection"] = "Encryption, privacy settings, browser security, and certificates",
        ["Patch & Config Management"] = "OS/app updates, software inventory, registry, and group policy",
        ["System Hardening"] = "System-level security, PowerShell restrictions, and virtualization",
        ["Resilience & Recovery"] = "Backups, event logging, and scheduled task security",
    };

    /// <summary>
    /// Assess the maturity of the system based on a completed security report.
    /// </summary>
    public MaturityAssessment Assess(SecurityReport report)
    {
        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .ToList();

        // Group findings by domain
        var domainFindings = new Dictionary<string, List<Finding>>();
        foreach (var domain in DomainDescriptions.Keys)
            domainFindings[domain] = [];

        foreach (var finding in allFindings)
        {
            var domain = CategoryToDomain.GetValueOrDefault(finding.Category, "System Hardening");
            if (!domainFindings.ContainsKey(domain))
                domainFindings[domain] = [];
            domainFindings[domain].Add(finding);
        }

        var domains = new List<MaturityDomain>();

        foreach (var (domainName, findings) in domainFindings)
        {
            var total = findings.Count;
            var passed = findings.Count(f => f.Severity == Severity.Pass);
            var criticals = findings.Count(f => f.Severity == Severity.Critical);
            var warnings = findings.Count(f => f.Severity == Severity.Warning);
            var infos = findings.Count(f => f.Severity == Severity.Info);

            // Score: each pass = 3pts, info = 1pt, warning = 0, critical = -1
            var score = (passed * 3) + (infos * 1) + (warnings * 0) + (criticals * -1);
            var maxScore = total * 3;
            var pct = maxScore > 0 ? score * 100.0 / maxScore : 0;

            var level = pct switch
            {
                >= 90 => MaturityLevel.Optimizing,
                >= 75 => MaturityLevel.Managed,
                >= 55 => MaturityLevel.Defined,
                >= 35 => MaturityLevel.Repeatable,
                _ => MaturityLevel.Initial,
            };

            var strengths = findings
                .Where(f => f.Severity == Severity.Pass)
                .Select(f => f.Title)
                .Take(3)
                .ToArray();

            var gaps = findings
                .Where(f => f.Severity == Severity.Critical)
                .Select(f => f.Title)
                .Concat(findings.Where(f => f.Severity == Severity.Warning).Select(f => f.Title))
                .Take(3)
                .ToArray();

            var recommendations = GenerateRecommendations(domainName, level, criticals, warnings).ToArray();

            domains.Add(new MaturityDomain
            {
                Name = domainName,
                Description = DomainDescriptions.GetValueOrDefault(domainName, ""),
                Level = level,
                Score = Math.Max(0, score),
                MaxScore = maxScore,
                Strengths = strengths,
                Gaps = gaps,
                Recommendations = recommendations,
            });
        }

        var overallScore = domains.Count > 0
            ? Math.Round(domains.Average(d => (int)d.Level), 1)
            : 1.0;

        var overallLevel = (MaturityLevel)Math.Round(overallScore);

        var grade = overallLevel switch
        {
            MaturityLevel.Optimizing => "A",
            MaturityLevel.Managed => "B",
            MaturityLevel.Defined => "C",
            MaturityLevel.Repeatable => "D",
            _ => "F",
        };

        var topPriorities = domains
            .Where(d => d.Level <= MaturityLevel.Repeatable)
            .OrderBy(d => d.Level)
            .ThenByDescending(d => d.Gaps.Length)
            .Select(d => $"Improve {d.Name} (currently Level {(int)d.Level} – {d.Level})")
            .Take(3)
            .ToArray();

        return new MaturityAssessment
        {
            OverallLevel = overallLevel,
            OverallScore = overallScore,
            Grade = grade,
            Domains = domains,
            TopPriorities = topPriorities,
            TotalFindings = allFindings.Count,
            CriticalFindings = allFindings.Count(f => f.Severity == Severity.Critical),
            WarningFindings = allFindings.Count(f => f.Severity == Severity.Warning),
        };
    }

    private static IEnumerable<string> GenerateRecommendations(string domain, MaturityLevel level, int criticals, int warnings)
    {
        if (criticals > 0)
            yield return $"Address {criticals} critical finding(s) immediately";

        if (warnings > 0)
            yield return $"Remediate {warnings} warning(s) to improve posture";

        switch (domain)
        {
            case "Identity & Access" when level < MaturityLevel.Managed:
                yield return "Enable MFA and review account policies";
                break;
            case "Network Security" when level < MaturityLevel.Managed:
                yield return "Tighten firewall rules and disable unused protocols";
                break;
            case "Endpoint Protection" when level < MaturityLevel.Managed:
                yield return "Ensure real-time protection is enabled and drivers are signed";
                break;
            case "Data Protection" when level < MaturityLevel.Managed:
                yield return "Enable full-disk encryption and review certificate stores";
                break;
            case "Patch & Config Management" when level < MaturityLevel.Managed:
                yield return "Enable automatic updates and remove unauthorized software";
                break;
            case "System Hardening" when level < MaturityLevel.Managed:
                yield return "Restrict PowerShell execution policy and enable audit logging";
                break;
            case "Resilience & Recovery" when level < MaturityLevel.Managed:
                yield return "Configure automated backups and secure event log retention";
                break;
        }

        if (level >= MaturityLevel.Managed)
            yield return "Maintain current controls and monitor for regression";
    }
}
