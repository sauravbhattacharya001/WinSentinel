using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes dependencies between security findings to identify root causes
/// and downstream effects.
/// <para>
/// Many security findings are consequences of other, more fundamental issues.
/// For example, if the Windows Firewall is disabled, many network-related
/// findings are downstream effects. Fixing the root cause resolves multiple
/// findings at once.
/// </para>
/// <para>
/// Example usage:
/// <code>
/// var graph = new FindingDependencyGraph();
/// var analysis = graph.Analyze(auditReport.GetAllFindings());
/// // Shows: "Windows Firewall Disabled" → causes 5 downstream findings
/// // Recommendation: Fix root causes first for maximum impact
/// </code>
/// </para>
/// </summary>
public class FindingDependencyGraph
{
    /// <summary>A known dependency rule: if the cause pattern matches, dependents are downstream.</summary>
    public class DependencyRule
    {
        /// <summary>Pattern that matches the root-cause finding title (case-insensitive substring).</summary>
        public required string CausePattern { get; init; }

        /// <summary>Category of the root-cause finding.</summary>
        public string? CauseCategory { get; init; }

        /// <summary>Patterns that match downstream/dependent findings.</summary>
        public required List<string> DependentPatterns { get; init; }

        /// <summary>Human-readable explanation of why this dependency exists.</summary>
        public required string Reason { get; init; }
    }

    /// <summary>Result of a dependency analysis for a single root-cause finding.</summary>
    public class DependencyNode
    {
        /// <summary>The root-cause finding.</summary>
        public required Finding RootCause { get; init; }

        /// <summary>Findings that are downstream/dependent on this root cause.</summary>
        public List<Finding> Dependents { get; init; } = [];

        /// <summary>The rule that matched.</summary>
        public required DependencyRule Rule { get; init; }

        /// <summary>Estimated impact if root cause is fixed (number of findings potentially resolved).</summary>
        public int Impact => Dependents.Count;
    }

    /// <summary>Full analysis result.</summary>
    public class DependencyAnalysis
    {
        /// <summary>Root causes with their dependent findings, sorted by impact.</summary>
        public List<DependencyNode> RootCauses { get; init; } = [];

        /// <summary>Findings that appear as dependents of at least one root cause.</summary>
        public HashSet<string> DependentTitles { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Findings with no known dependencies (independent).</summary>
        public List<Finding> IndependentFindings { get; init; } = [];

        /// <summary>Total findings analyzed.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Total dependency links found.</summary>
        public int TotalLinks => RootCauses.Sum(r => r.Dependents.Count);

        /// <summary>
        /// Dependency density: ratio of linked findings to total findings.
        /// Higher means more findings are interconnected.
        /// </summary>
        public double DependencyDensity => TotalFindings > 0
            ? (double)(RootCauses.Count + RootCauses.Sum(r => r.Dependents.Count)) / TotalFindings
            : 0;
    }

    /// <summary>Built-in dependency rules based on common Windows security patterns.</summary>
    private static readonly List<DependencyRule> _builtinRules =
    [
        new()
        {
            CausePattern = "firewall",
            CauseCategory = "Firewall",
            DependentPatterns = ["open port", "inbound rule", "smb", "rdp exposed", "remote desktop", "network share"],
            Reason = "Firewall issues leave network services exposed"
        },
        new()
        {
            CausePattern = "windows update",
            CauseCategory = "Updates",
            DependentPatterns = ["patch", "vulnerability", "cve", "outdated", "end of life", "unsupported"],
            Reason = "Missing updates leave known vulnerabilities unpatched"
        },
        new()
        {
            CausePattern = "antivirus",
            DependentPatterns = ["malware", "real-time protection", "virus definition", "scan", "threat detection"],
            Reason = "Disabled antivirus allows malware threats to go undetected"
        },
        new()
        {
            CausePattern = "password policy",
            CauseCategory = "Accounts",
            DependentPatterns = ["weak password", "password age", "password length", "password complexity", "account lockout"],
            Reason = "Weak password policies lead to multiple credential weaknesses"
        },
        new()
        {
            CausePattern = "uac",
            DependentPatterns = ["admin", "elevated", "privilege", "consent prompt"],
            Reason = "Disabled UAC allows unrestricted privilege escalation"
        },
        new()
        {
            CausePattern = "audit policy",
            CauseCategory = "Audit",
            DependentPatterns = ["event log", "logging", "audit failure", "logon event", "object access"],
            Reason = "Missing audit policies lead to gaps in security logging"
        },
        new()
        {
            CausePattern = "bitlocker",
            DependentPatterns = ["disk encryption", "tpm", "recovery key", "drive encrypt"],
            Reason = "Missing disk encryption exposes data-at-rest vulnerabilities"
        },
        new()
        {
            CausePattern = "remote desktop",
            DependentPatterns = ["rdp", "nla", "network level auth", "remote session", "terminal service"],
            Reason = "Insecure RDP configuration enables multiple remote access risks"
        },
        new()
        {
            CausePattern = "guest account",
            CauseCategory = "Accounts",
            DependentPatterns = ["anonymous", "null session", "unauthenticated", "anonymous access"],
            Reason = "Enabled guest/anonymous access weakens authentication controls"
        },
        new()
        {
            CausePattern = "smb",
            DependentPatterns = ["smbv1", "smb signing", "network share permission", "share access"],
            Reason = "SMB misconfigurations cascade into share-level vulnerabilities"
        },
        new()
        {
            CausePattern = "tls",
            DependentPatterns = ["ssl", "cipher", "certificate", "schannel", "weak protocol"],
            Reason = "TLS/SSL misconfigurations affect all encrypted communication"
        },
        new()
        {
            CausePattern = "group policy",
            DependentPatterns = ["gpo", "security template", "local policy", "policy refresh"],
            Reason = "Group Policy issues prevent security settings from being enforced"
        }
    ];

    /// <summary>
    /// Analyze findings for dependency relationships.
    /// </summary>
    /// <param name="findings">All findings from an audit.</param>
    /// <returns>Dependency analysis showing root causes and their downstream effects.</returns>
    public DependencyAnalysis Analyze(IReadOnlyList<Finding> findings)
    {
        var rootCauses = new List<DependencyNode>();
        var dependentTitles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in _builtinRules)
        {
            // Find the root-cause finding
            var cause = findings.FirstOrDefault(f =>
                f.Title.Contains(rule.CausePattern, StringComparison.OrdinalIgnoreCase) &&
                (rule.CauseCategory == null ||
                 f.Category.Equals(rule.CauseCategory, StringComparison.OrdinalIgnoreCase)));

            if (cause == null) continue;

            // Find dependent findings
            var dependents = findings
                .Where(f => f != cause && rule.DependentPatterns.Any(p =>
                    f.Title.Contains(p, StringComparison.OrdinalIgnoreCase) ||
                    f.Description.Contains(p, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (dependents.Count == 0) continue;

            rootCauses.Add(new DependencyNode
            {
                RootCause = cause,
                Dependents = dependents,
                Rule = rule
            });

            foreach (var d in dependents)
                dependentTitles.Add(d.Title);
        }

        // Sort by impact (most dependents first)
        rootCauses.Sort((a, b) => b.Impact.CompareTo(a.Impact));

        // Independent findings: not a root cause and not a dependent
        var rootTitles = rootCauses.Select(r => r.RootCause.Title).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var independentFindings = findings
            .Where(f => !rootTitles.Contains(f.Title) && !dependentTitles.Contains(f.Title))
            .ToList();

        return new DependencyAnalysis
        {
            RootCauses = rootCauses,
            DependentTitles = dependentTitles,
            IndependentFindings = independentFindings,
            TotalFindings = findings.Count
        };
    }

    /// <summary>
    /// Format the analysis as a text report.
    /// </summary>
    public static string FormatText(DependencyAnalysis analysis)
    {
        var sb = new StringBuilder();

        sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║           FINDING DEPENDENCY GRAPH                          ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();

        // Summary
        sb.AppendLine($"  Total Findings:     {analysis.TotalFindings}");
        sb.AppendLine($"  Root Causes:        {analysis.RootCauses.Count}");
        sb.AppendLine($"  Dependency Links:   {analysis.TotalLinks}");
        sb.AppendLine($"  Independent:        {analysis.IndependentFindings.Count}");
        sb.AppendLine($"  Dependency Density: {analysis.DependencyDensity:P0}");
        sb.AppendLine();

        if (analysis.RootCauses.Count == 0)
        {
            sb.AppendLine("  No dependency patterns detected among current findings.");
            sb.AppendLine("  All findings appear to be independent issues.");
            return sb.ToString();
        }

        // Prioritized fix order
        sb.AppendLine("┌──────────────────────────────────────────────────────────────┐");
        sb.AppendLine("│  PRIORITY FIX ORDER (fix root causes for maximum impact)     │");
        sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
        sb.AppendLine();

        for (int i = 0; i < analysis.RootCauses.Count; i++)
        {
            var node = analysis.RootCauses[i];
            var sevIcon = node.RootCause.Severity switch
            {
                Severity.Critical => "🔴",
                Severity.Warning => "🟠",
                Severity.Info => "🟡",
                Severity.Pass => "🟢",
                _ => "⚪"
            };

            sb.AppendLine($"  #{i + 1}  {sevIcon} {node.RootCause.Title}");
            sb.AppendLine($"      Category: {node.RootCause.Category} | Severity: {node.RootCause.Severity}");
            sb.AppendLine($"      Impact: Fixing this may resolve {node.Impact} downstream finding(s)");
            sb.AppendLine($"      Why: {node.Rule.Reason}");
            sb.AppendLine();

            foreach (var dep in node.Dependents)
            {
                var dSev = dep.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.Warning => "🟠",
                    Severity.Info => "🟡",
                    Severity.Pass => "🟢",
                    _ => "⚪"
                };
                sb.AppendLine($"        └─ {dSev} {dep.Title} [{dep.Category}]");
            }
            sb.AppendLine();
        }

        // Impact summary
        var totalResolvable = analysis.RootCauses.Sum(r => r.Dependents.Count);
        sb.AppendLine("┌──────────────────────────────────────────────────────────────┐");
        sb.AppendLine("│  IMPACT SUMMARY                                              │");
        sb.AppendLine("└──────────────────────────────────────────────────────────────┘");
        sb.AppendLine();
        sb.AppendLine($"  By fixing {analysis.RootCauses.Count} root cause(s), you could");
        sb.AppendLine($"  potentially resolve up to {totalResolvable} additional finding(s).");
        sb.AppendLine();

        if (analysis.IndependentFindings.Count > 0)
        {
            sb.AppendLine($"  {analysis.IndependentFindings.Count} finding(s) are independent and must be fixed individually.");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Format the analysis as JSON.
    /// </summary>
    public static string FormatJson(DependencyAnalysis analysis)
    {
        var obj = new
        {
            summary = new
            {
                totalFindings = analysis.TotalFindings,
                rootCauses = analysis.RootCauses.Count,
                dependencyLinks = analysis.TotalLinks,
                independentFindings = analysis.IndependentFindings.Count,
                dependencyDensity = Math.Round(analysis.DependencyDensity, 3)
            },
            rootCauses = analysis.RootCauses.Select(n => new
            {
                finding = n.RootCause.Title,
                category = n.RootCause.Category,
                severity = n.RootCause.Severity.ToString(),
                impact = n.Impact,
                reason = n.Rule.Reason,
                dependents = n.Dependents.Select(d => new
                {
                    title = d.Title,
                    category = d.Category,
                    severity = d.Severity.ToString()
                })
            }),
            independentFindings = analysis.IndependentFindings.Select(f => new
            {
                title = f.Title,
                category = f.Category,
                severity = f.Severity.ToString()
            })
        };

        return System.Text.Json.JsonSerializer.Serialize(obj,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Format the analysis as Markdown.
    /// </summary>
    public static string FormatMarkdown(DependencyAnalysis analysis)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Finding Dependency Graph");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| Total Findings | {analysis.TotalFindings} |");
        sb.AppendLine($"| Root Causes | {analysis.RootCauses.Count} |");
        sb.AppendLine($"| Dependency Links | {analysis.TotalLinks} |");
        sb.AppendLine($"| Independent | {analysis.IndependentFindings.Count} |");
        sb.AppendLine($"| Dependency Density | {analysis.DependencyDensity:P0} |");
        sb.AppendLine();

        if (analysis.RootCauses.Count == 0)
        {
            sb.AppendLine("No dependency patterns detected. All findings are independent.");
            return sb.ToString();
        }

        sb.AppendLine("## Priority Fix Order");
        sb.AppendLine();

        for (int i = 0; i < analysis.RootCauses.Count; i++)
        {
            var node = analysis.RootCauses[i];
            sb.AppendLine($"### #{i + 1} — {node.RootCause.Title}");
            sb.AppendLine();
            sb.AppendLine($"- **Category:** {node.RootCause.Category}");
            sb.AppendLine($"- **Severity:** {node.RootCause.Severity}");
            sb.AppendLine($"- **Impact:** {node.Impact} downstream finding(s)");
            sb.AppendLine($"- **Why:** {node.Rule.Reason}");
            sb.AppendLine();
            sb.AppendLine("| Dependent Finding | Category | Severity |");
            sb.AppendLine("|-------------------|----------|----------|");
            foreach (var dep in node.Dependents)
                sb.AppendLine($"| {dep.Title} | {dep.Category} | {dep.Severity} |");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
