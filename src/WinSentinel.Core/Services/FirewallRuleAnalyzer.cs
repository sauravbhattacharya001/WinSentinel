using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Deep security analysis of individual firewall rules.
/// Detects overly permissive rules, dangerous ports, shadow/duplicate rules,
/// rule staleness, and generates a comprehensive security report.
/// </summary>
public class FirewallRuleAnalyzer
{
    /// <summary>Known dangerous ports that should not be exposed without justification.</summary>
    public static readonly Dictionary<int, string> DangerousPorts = new()
    {
        { 21, "FTP — plaintext credentials" },
        { 23, "Telnet — plaintext protocol" },
        { 135, "RPC Endpoint Mapper — worm target" },
        { 139, "NetBIOS — lateral movement vector" },
        { 445, "SMB — ransomware propagation" },
        { 1433, "SQL Server — database exposure" },
        { 1434, "SQL Server Browser — discovery" },
        { 3389, "RDP — brute-force target" },
        { 5900, "VNC — remote desktop" },
        { 5985, "WinRM HTTP — remote management" },
        { 5986, "WinRM HTTPS — remote management" },
        { 6379, "Redis — unauthenticated by default" },
        { 27017, "MongoDB — unauthenticated by default" },
    };

    /// <summary>
    /// Represents a parsed firewall rule for analysis.
    /// </summary>
    public class FirewallRule
    {
        public string Name { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public string Direction { get; set; } = "In"; // In or Out
        public string Action { get; set; } = "Allow"; // Allow or Block
        public string Protocol { get; set; } = "Any";
        public string LocalPort { get; set; } = "Any";
        public string RemotePort { get; set; } = "Any";
        public string RemoteAddress { get; set; } = "Any";
        public string LocalAddress { get; set; } = "Any";
        public string Program { get; set; } = "Any";
        public string Profile { get; set; } = "Any"; // Domain, Private, Public, Any
        public string Grouping { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Complete state for testable analysis.
    /// </summary>
    public class FirewallRuleState
    {
        public List<FirewallRule> Rules { get; set; } = new();
    }

    /// <summary>
    /// Result of the deep firewall rule analysis.
    /// </summary>
    public class FirewallAnalysisReport
    {
        public int TotalRules { get; set; }
        public int EnabledRules { get; set; }
        public int DisabledRules { get; set; }
        public int InboundAllowRules { get; set; }
        public int OutboundBlockRules { get; set; }
        public List<RuleRisk> RiskyRules { get; set; } = new();
        public List<DuplicateGroup> DuplicateGroups { get; set; } = new();
        public List<ShadowedRule> ShadowedRules { get; set; } = new();
        public int OverlyPermissiveCount { get; set; }
        public int DangerousPortCount { get; set; }
        public int PublicProfileExposureCount { get; set; }
        public double RiskScore { get; set; } // 0-100, higher = riskier
    }

    public class RuleRisk
    {
        public FirewallRule Rule { get; set; } = new();
        public string RiskReason { get; set; } = string.Empty;
        public Severity Severity { get; set; }
    }

    public class DuplicateGroup
    {
        public List<string> RuleNames { get; set; } = new();
        public string MatchReason { get; set; } = string.Empty;
    }

    public class ShadowedRule
    {
        public string RuleName { get; set; } = string.Empty;
        public string ShadowedBy { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>
    /// Analyze firewall rules and produce findings.
    /// </summary>
    public List<Finding> Analyze(FirewallRuleState state)
    {
        var findings = new List<Finding>();
        var report = BuildReport(state);

        // Summary
        findings.Add(Finding.Info(
            "Firewall Rule Summary",
            $"Total: {report.TotalRules} rules ({report.EnabledRules} enabled, {report.DisabledRules} disabled). " +
            $"Inbound Allow: {report.InboundAllowRules}. Risk Score: {report.RiskScore:F0}/100.",
            "Firewall"));

        // Risky rules
        foreach (var risk in report.RiskyRules)
        {
            findings.Add(new Finding
            {
                Title = $"Risky Rule: {risk.Rule.Name}",
                Description = risk.RiskReason,
                Severity = risk.Severity,
                Category = "Firewall",
                Remediation = GetRemediation(risk),
            });
        }

        // Duplicates
        foreach (var dup in report.DuplicateGroups)
        {
            findings.Add(Finding.Info(
                "Duplicate Firewall Rules",
                $"Rules [{string.Join(", ", dup.RuleNames)}] appear to be duplicates ({dup.MatchReason}). Consider consolidating.",
                "Firewall",
                "Remove duplicate rules to simplify firewall management."));
        }

        // Shadowed rules
        foreach (var shadow in report.ShadowedRules)
        {
            findings.Add(Finding.Warning(
                $"Shadowed Rule: {shadow.RuleName}",
                $"Rule '{shadow.RuleName}' is shadowed by '{shadow.ShadowedBy}': {shadow.Reason}",
                "Firewall",
                "Review shadowed rules — they may be redundant or indicate misconfiguration."));
        }

        // Overall assessment
        if (report.RiskScore >= 70)
        {
            findings.Add(Finding.Critical(
                "High Firewall Risk Score",
                $"Firewall risk score is {report.RiskScore:F0}/100. Multiple risky configurations detected.",
                "Firewall",
                "Urgently review and tighten firewall rules."));
        }
        else if (report.RiskScore >= 40)
        {
            findings.Add(Finding.Warning(
                "Moderate Firewall Risk Score",
                $"Firewall risk score is {report.RiskScore:F0}/100. Some rules need attention.",
                "Firewall",
                "Review flagged rules and restrict where possible."));
        }
        else if (report.RiskScore > 0)
        {
            findings.Add(Finding.Pass(
                "Low Firewall Risk Score",
                $"Firewall risk score is {report.RiskScore:F0}/100. Configuration looks reasonable.",
                "Firewall"));
        }

        return findings;
    }

    /// <summary>
    /// Build a detailed analysis report from rule state.
    /// </summary>
    public FirewallAnalysisReport BuildReport(FirewallRuleState state)
    {
        var report = new FirewallAnalysisReport
        {
            TotalRules = state.Rules.Count,
            EnabledRules = state.Rules.Count(r => r.Enabled),
            DisabledRules = state.Rules.Count(r => !r.Enabled),
        };

        var enabled = state.Rules.Where(r => r.Enabled).ToList();
        report.InboundAllowRules = enabled.Count(r =>
            r.Direction.Equals("In", StringComparison.OrdinalIgnoreCase) &&
            r.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase));
        report.OutboundBlockRules = enabled.Count(r =>
            r.Direction.Equals("Out", StringComparison.OrdinalIgnoreCase) &&
            r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase));

        CheckOverlyPermissiveRules(enabled, report);
        CheckDangerousPorts(enabled, report);
        CheckPublicProfileExposure(enabled, report);
        CheckProgramlessRules(enabled, report);
        FindDuplicates(enabled, report);
        FindShadowedRules(enabled, report);
        CalculateRiskScore(report);

        return report;
    }

    private void CheckOverlyPermissiveRules(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        foreach (var rule in rules)
        {
            if (!rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) continue;
            if (!rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase)) continue;

            bool anyProtocol = rule.Protocol.Equals("Any", StringComparison.OrdinalIgnoreCase);
            bool anyPort = rule.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase);
            bool anyRemote = rule.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase);
            bool anyProgram = rule.Program.Equals("Any", StringComparison.OrdinalIgnoreCase);

            // Fully open rule: any protocol, any port, any remote, any program
            if (anyProtocol && anyPort && anyRemote && anyProgram)
            {
                report.OverlyPermissiveCount++;
                report.RiskyRules.Add(new RuleRisk
                {
                    Rule = rule,
                    RiskReason = "Allows ALL inbound traffic (any protocol, port, address, program). This effectively disables the firewall for this rule.",
                    Severity = Severity.Critical
                });
                continue;
            }

            // Any port + any remote (but specific protocol)
            if (anyPort && anyRemote && anyProgram &&
                (rule.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
                 rule.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase)))
            {
                report.OverlyPermissiveCount++;
                report.RiskyRules.Add(new RuleRisk
                {
                    Rule = rule,
                    RiskReason = $"Allows inbound {rule.Protocol} on ALL ports from ANY address with no program restriction.",
                    Severity = Severity.Warning
                });
            }
        }
    }

    private void CheckDangerousPorts(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        foreach (var rule in rules)
        {
            if (!rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) continue;
            if (!rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase)) continue;

            var ports = ParsePorts(rule.LocalPort);
            foreach (var port in ports)
            {
                if (DangerousPorts.TryGetValue(port, out var reason))
                {
                    bool anyRemote = rule.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase);
                    var severity = anyRemote ? Severity.Critical : Severity.Warning;

                    report.DangerousPortCount++;
                    report.RiskyRules.Add(new RuleRisk
                    {
                        Rule = rule,
                        RiskReason = $"Exposes port {port} ({reason}){(anyRemote ? " to ANY remote address" : " with remote restriction")}.",
                        Severity = severity
                    });
                }
            }
        }
    }

    private void CheckPublicProfileExposure(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        foreach (var rule in rules)
        {
            if (!rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) continue;
            if (!rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase)) continue;

            var profile = rule.Profile;
            bool appliesToPublic = profile.Equals("Any", StringComparison.OrdinalIgnoreCase) ||
                                   profile.Contains("Public", StringComparison.OrdinalIgnoreCase);

            if (!appliesToPublic) continue;

            bool anyRemote = rule.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase);
            if (!anyRemote) continue;

            // Check if it's exposing a service on public network
            bool anyPort = rule.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase);
            if (anyPort || ParsePorts(rule.LocalPort).Any())
            {
                report.PublicProfileExposureCount++;
                report.RiskyRules.Add(new RuleRisk
                {
                    Rule = rule,
                    RiskReason = $"Rule '{rule.Name}' allows inbound on Public profile from any address. Services should not be exposed on untrusted networks.",
                    Severity = Severity.Warning
                });
            }
        }
    }

    private void CheckProgramlessRules(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        foreach (var rule in rules)
        {
            if (!rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) continue;
            if (!rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase)) continue;
            if (!rule.Program.Equals("Any", StringComparison.OrdinalIgnoreCase)) continue;

            // Only flag if also not port-restricted
            bool anyPort = rule.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase);
            if (anyPort) continue; // Already caught by overly permissive

            // Port-specific but no program — minor issue
            var ports = ParsePorts(rule.LocalPort);
            if (ports.Count > 0)
            {
                report.RiskyRules.Add(new RuleRisk
                {
                    Rule = rule,
                    RiskReason = $"Allows inbound on port(s) {rule.LocalPort} without restricting to a specific program. Any program could listen on these ports.",
                    Severity = Severity.Info
                });
            }
        }
    }

    private void FindDuplicates(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        var seen = new Dictionary<string, List<string>>();

        foreach (var rule in rules)
        {
            // Key by direction+action+protocol+port+remote
            var key = $"{rule.Direction}|{rule.Action}|{rule.Protocol}|{rule.LocalPort}|{rule.RemoteAddress}|{rule.Program}"
                .ToUpperInvariant();
            if (!seen.ContainsKey(key))
                seen[key] = new List<string>();
            seen[key].Add(rule.Name);
        }

        foreach (var (key, names) in seen)
        {
            if (names.Count > 1)
            {
                report.DuplicateGroups.Add(new DuplicateGroup
                {
                    RuleNames = names,
                    MatchReason = "Same direction, action, protocol, port, remote address, and program."
                });
            }
        }
    }

    private void FindShadowedRules(List<FirewallRule> rules, FirewallAnalysisReport report)
    {
        // A specific allow rule is shadowed if a broader allow rule already covers it
        var inboundAllow = rules
            .Where(r => r.Direction.Equals("In", StringComparison.OrdinalIgnoreCase) &&
                        r.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var narrow in inboundAllow)
        {
            foreach (var broad in inboundAllow)
            {
                if (ReferenceEquals(narrow, broad)) continue;

                if (IsBroaderThan(broad, narrow))
                {
                    report.ShadowedRules.Add(new ShadowedRule
                    {
                        RuleName = narrow.Name,
                        ShadowedBy = broad.Name,
                        Reason = $"'{broad.Name}' already covers everything '{narrow.Name}' allows."
                    });
                    break; // Only report first shadow
                }
            }
        }
    }

    /// <summary>
    /// Returns true if 'broad' rule covers everything 'narrow' allows.
    /// </summary>
    public static bool IsBroaderThan(FirewallRule broad, FirewallRule narrow)
    {
        // broad must be at least as permissive in every dimension
        if (!Covers(broad.Protocol, narrow.Protocol)) return false;
        if (!Covers(broad.LocalPort, narrow.LocalPort)) return false;
        if (!Covers(broad.RemoteAddress, narrow.RemoteAddress)) return false;
        if (!Covers(broad.Program, narrow.Program)) return false;
        if (!ProfileCovers(broad.Profile, narrow.Profile)) return false;

        // At least one dimension must be strictly broader
        bool strictlyBroader =
            IsStrictlyBroader(broad.Protocol, narrow.Protocol) ||
            IsStrictlyBroader(broad.LocalPort, narrow.LocalPort) ||
            IsStrictlyBroader(broad.RemoteAddress, narrow.RemoteAddress) ||
            IsStrictlyBroader(broad.Program, narrow.Program);

        return strictlyBroader;
    }

    private static bool Covers(string broad, string narrow)
    {
        if (broad.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
        return broad.Equals(narrow, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ProfileCovers(string broad, string narrow)
    {
        if (broad.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
        if (broad.Equals(narrow, StringComparison.OrdinalIgnoreCase)) return true;

        // Check if broad profile set contains narrow
        var broadProfiles = broad.Split(',', StringSplitOptions.TrimEntries)
            .Select(p => p.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var narrowProfiles = narrow.Split(',', StringSplitOptions.TrimEntries)
            .Select(p => p.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);

        return narrowProfiles.IsSubsetOf(broadProfiles);
    }

    private static bool IsStrictlyBroader(string broad, string narrow)
    {
        if (broad.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
            !narrow.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private void CalculateRiskScore(FirewallAnalysisReport report)
    {
        double score = 0;

        foreach (var risk in report.RiskyRules)
        {
            score += risk.Severity switch
            {
                Severity.Critical => 15,
                Severity.Warning => 5,
                Severity.Info => 1,
                _ => 0
            };
        }

        score += report.DuplicateGroups.Count * 2;
        score += report.ShadowedRules.Count * 1;

        report.RiskScore = Math.Min(100, score);
    }

    /// <summary>
    /// Parse a port spec like "80", "80,443", "1000-2000", or "Any" into individual ports.
    /// For ranges, returns the start and end ports (not every port in between).
    /// </summary>
    public static List<int> ParsePorts(string portSpec)
    {
        if (string.IsNullOrWhiteSpace(portSpec) ||
            portSpec.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return new List<int>();

        var result = new List<int>();
        var parts = portSpec.Split(',', StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-');
                if (range.Length == 2 &&
                    int.TryParse(range[0], out var start) &&
                    int.TryParse(range[1], out var end))
                {
                    result.Add(start);
                    if (end != start) result.Add(end);
                }
            }
            else if (int.TryParse(part, out var port))
            {
                result.Add(port);
            }
        }
        return result;
    }

    private static string GetRemediation(RuleRisk risk)
    {
        return risk.Severity switch
        {
            Severity.Critical => $"Disable or restrict rule '{risk.Rule.Name}' immediately. Limit to specific ports, addresses, or programs.",
            Severity.Warning => $"Review rule '{risk.Rule.Name}' and restrict scope where possible.",
            _ => $"Consider tightening rule '{risk.Rule.Name}'."
        };
    }
}
