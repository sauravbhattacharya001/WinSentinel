using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes findings across modules to identify dependency relationships —
/// which root findings, when fixed, would cascade-resolve related findings.
/// </summary>
public class FindingDependencyAnalyzer
{
    // Known dependency rules: (root pattern, dependent pattern, relationship type, reason)
    private static readonly List<DependencyRule> Rules = new()
    {
        // Firewall disabled → network exposure findings
        new("Firewall.*disabled", "Network", "firewall-network",
            "Firewall being disabled exposes network services"),
        new("Firewall.*disabled", ".*listening.*port", "firewall-network",
            "Open ports are only risky because firewall is disabled"),
        new("Firewall.*disabled", "SMB", "firewall-smb",
            "SMB exposure depends on firewall state"),
        new("Firewall.*disabled", "Remote Desktop", "firewall-rdp",
            "RDP exposure depends on firewall state"),

        // Windows Update disabled → outdated software
        new("Windows Update.*disabled", ".*outdated", "update-software",
            "Outdated software is a symptom of disabled updates"),
        new("Windows Update.*disabled", ".*update.*missing", "update-patch",
            "Missing patches are caused by disabled updates"),
        new("Automatic Updates.*disabled", ".*outdated", "update-software",
            "Outdated software is a symptom of disabled auto-updates"),

        // Defender disabled → malware/threat findings
        new("Defender.*disabled", ".*malware", "defender-malware",
            "Malware detection requires Defender to be enabled"),
        new("Defender.*disabled", "Real-time.*protection", "defender-realtime",
            "Real-time protection is a Defender feature"),
        new("Defender.*disabled", ".*antivirus", "defender-av",
            "Antivirus functionality depends on Defender"),

        // UAC disabled → privilege escalation
        new("UAC.*disabled", ".*admin.*privilege", "uac-privilege",
            "Admin privilege issues stem from UAC being disabled"),
        new("UAC.*disabled", ".*elevation", "uac-elevation",
            "Elevation issues depend on UAC configuration"),

        // No password policy → weak credentials
        new("Password.*policy", ".*weak.*password", "policy-password",
            "Weak passwords are a symptom of missing password policy"),
        new("Password.*policy", ".*password.*expir", "policy-expiry",
            "Password expiry issues depend on password policy"),
        new("Password.*complexity", ".*weak.*password", "complexity-password",
            "Weak passwords result from no complexity requirements"),

        // Encryption disabled → data exposure
        new("BitLocker.*not.*enabled", ".*unencrypted", "bitlocker-encrypt",
            "Unencrypted data findings depend on BitLocker being enabled"),
        new("BitLocker.*not.*enabled", ".*data.*exposure", "bitlocker-data",
            "Data exposure risk stems from missing disk encryption"),

        // Audit policy → event log gaps
        new("Audit.*policy.*not.*configured", ".*event.*log", "audit-eventlog",
            "Event log gaps are caused by missing audit policy"),
        new("Audit.*policy.*not.*configured", ".*logging.*disabled", "audit-logging",
            "Disabled logging stems from missing audit policy"),

        // Guest account → unauthorized access
        new("Guest.*account.*enabled", ".*unauthorized.*access", "guest-access",
            "Unauthorized access risk increases with guest account enabled"),

        // Remote Desktop enabled → remote attack surface
        new("Remote Desktop.*enabled", ".*remote.*attack", "rdp-attack",
            "Remote attack surface includes RDP when enabled"),
        new("Remote Desktop.*enabled", ".*NLA.*not.*required", "rdp-nla",
            "NLA requirement is only relevant when RDP is enabled"),

        // PowerShell execution policy → script risks
        new("PowerShell.*Unrestricted", ".*script.*execution", "ps-script",
            "Script execution risks depend on PowerShell execution policy"),
        new("PowerShell.*execution.*policy", ".*unsigned.*script", "ps-unsigned",
            "Unsigned script risks depend on execution policy"),

        // Shared folder → data leakage
        new(".*shared.*folder.*permission", ".*share.*access", "share-access",
            "Share access issues depend on folder permissions"),

        // Certificate issues → TLS/SSL problems
        new(".*certificate.*expired", ".*TLS", "cert-tls",
            "TLS issues may stem from expired certificates"),
        new(".*certificate.*expired", ".*SSL", "cert-ssl",
            "SSL issues may stem from expired certificates"),

        // DNS misconfiguration → resolution issues
        new("DNS.*misconfigured", ".*name.*resolution", "dns-resolution",
            "Name resolution issues depend on DNS configuration"),

        // Bluetooth enabled → wireless exposure
        new("Bluetooth.*enabled", ".*wireless.*exposure", "bt-wireless",
            "Wireless exposure includes Bluetooth when enabled"),
    };

    /// <summary>
    /// Analyze findings and build a dependency graph.
    /// </summary>
    public FindingDependencyResult Analyze(List<AuditResult> results, int topN = 10)
    {
        var allFindings = results
            .Where(r => r.Success)
            .SelectMany(r => r.Findings.Select(f => new FindingWithModule
            {
                Title = f.Title,
                Module = r.ModuleName,
                Category = f.Category,
                Severity = f.Severity,
                HasAutoFix = !string.IsNullOrWhiteSpace(f.FixCommand)
            }))
            .Where(f => f.Severity is Severity.Critical or Severity.Warning)
            .ToList();

        var clusters = new List<DependencyCluster>();
        var usedDependents = new HashSet<string>(); // track to avoid double-counting
        int clusterId = 0;

        foreach (var rule in Rules)
        {
            // Find root findings matching the rule
            var roots = allFindings
                .Where(f => System.Text.RegularExpressions.Regex.IsMatch(
                    f.Title, rule.RootPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                .ToList();

            foreach (var root in roots)
            {
                // Find dependent findings matching the rule
                var dependents = allFindings
                    .Where(f => f != root &&
                           !usedDependents.Contains(f.Key) &&
                           (System.Text.RegularExpressions.Regex.IsMatch(
                               f.Title, rule.DependentPattern,
                               System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                            System.Text.RegularExpressions.Regex.IsMatch(
                               f.Module, rule.DependentPattern,
                               System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                    .ToList();

                if (dependents.Count == 0) continue;

                clusterId++;
                var cluster = new DependencyCluster
                {
                    ClusterId = clusterId,
                    RootTitle = root.Title,
                    RootModule = root.Module,
                    RootSeverity = root.Severity,
                    RelationshipType = rule.RelationshipType,
                    Dependents = dependents.Select(d =>
                    {
                        usedDependents.Add(d.Key);
                        return new DependentFinding
                        {
                            Title = d.Title,
                            Module = d.Module,
                            Severity = d.Severity,
                            Reason = rule.Reason,
                            Depth = 1
                        };
                    }).ToList()
                };
                clusters.Add(cluster);
            }
        }

        // Also cluster by category for findings not yet in a cluster
        var unclustered = allFindings
            .Where(f => !usedDependents.Contains(f.Key) &&
                        !clusters.Any(c => c.RootTitle == f.Title && c.RootModule == f.Module))
            .GroupBy(f => f.Category)
            .Where(g => g.Count() >= 3)
            .ToList();

        foreach (var group in unclustered)
        {
            var sorted = group.OrderByDescending(f => f.Severity).ToList();
            var root = sorted[0];
            var deps = sorted.Skip(1).ToList();

            if (deps.Count == 0) continue;

            clusterId++;
            clusters.Add(new DependencyCluster
            {
                ClusterId = clusterId,
                RootTitle = root.Title,
                RootModule = root.Module,
                RootSeverity = root.Severity,
                RelationshipType = "category-group",
                Dependents = deps.Select(d => new DependentFinding
                {
                    Title = d.Title,
                    Module = d.Module,
                    Severity = d.Severity,
                    Reason = $"Same category: {group.Key}",
                    Depth = 1
                }).ToList()
            });
        }

        // Sort clusters by cascade impact
        clusters = clusters.OrderByDescending(c => c.CascadeCount).ToList();

        var topImpacts = clusters
            .Take(topN)
            .Select(c =>
            {
                var rootFinding = allFindings.FirstOrDefault(f =>
                    f.Title == c.RootTitle && f.Module == c.RootModule);

                return new CascadeImpact
                {
                    Title = c.RootTitle,
                    Module = c.RootModule,
                    Severity = c.RootSeverity,
                    CascadeCount = c.CascadeCount,
                    Category = rootFinding?.Category ?? "",
                    HasAutoFix = rootFinding?.HasAutoFix ?? false,
                    ScoreImpact = EstimateScoreImpact(c)
                };
            })
            .ToList();

        var totalDependents = clusters.Sum(c => c.CascadeCount);

        return new FindingDependencyResult
        {
            TotalFindings = allFindings.Count,
            RootFindings = clusters.Count,
            DependentFindings = totalDependents,
            MaxCascadeDepth = clusters.Count > 0 ? clusters.Max(c => c.Dependents.Max(d => d.Depth)) : 0,
            Clusters = clusters,
            TopCascadeImpacts = topImpacts,
            EstimatedAutoResolve = totalDependents
        };
    }

    private static double EstimateScoreImpact(DependencyCluster cluster)
    {
        double impact = 0;
        // Root finding impact
        impact += cluster.RootSeverity == Severity.Critical ? 5.0 : 2.5;
        // Each dependent
        foreach (var dep in cluster.Dependents)
        {
            impact += dep.Severity == Severity.Critical ? 3.0 : 1.5;
        }
        return Math.Round(impact, 1);
    }

    private class FindingWithModule
    {
        public string Title { get; set; } = string.Empty;
        public string Module { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public Severity Severity { get; set; }
        public bool HasAutoFix { get; set; }
        public string Key => $"{Module}::{Title}";
    }

    private record DependencyRule(
        string RootPattern,
        string DependentPattern,
        string RelationshipType,
        string Reason);
}
