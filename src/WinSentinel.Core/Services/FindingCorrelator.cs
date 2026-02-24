using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes findings across audit modules to detect correlated security risks.
/// Identifies compound vulnerabilities where multiple findings together
/// indicate a greater risk than the sum of their parts.
/// </summary>
public class FindingCorrelator
{
    /// <summary>Maximum number of correlation rules to process.</summary>
    public const int MaxRules = 200;

    /// <summary>
    /// A correlation rule that matches when specific finding patterns co-occur.
    /// </summary>
    public record CorrelationRule(
        string Id,
        string Name,
        string Description,
        string[] RequiredPatterns,    // Finding title substrings (case-insensitive)
        string[] RequiredCategories,  // At least one finding must be from each category
        Severity AmplifiedSeverity,
        string Recommendation
    );

    /// <summary>
    /// Result of a single correlation match.
    /// </summary>
    public record CorrelationMatch(
        CorrelationRule Rule,
        List<Finding> MatchedFindings,
        Severity OriginalMaxSeverity,
        Severity AmplifiedSeverity
    );

    /// <summary>
    /// Full correlation analysis result.
    /// </summary>
    public record CorrelationReport(
        int TotalFindings,
        int CorrelationsFound,
        List<CorrelationMatch> Matches,
        int RiskAmplification,  // How many findings got severity-amplified
        List<string> Recommendations
    );

    private readonly List<CorrelationRule> _rules = new();

    public FindingCorrelator()
    {
        LoadBuiltInRules();
    }

    /// <summary>
    /// Add a custom correlation rule.
    /// </summary>
    public void AddRule(CorrelationRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (string.IsNullOrWhiteSpace(rule.Id))
            throw new ArgumentException("Rule Id cannot be empty.");
        if (string.IsNullOrWhiteSpace(rule.Name))
            throw new ArgumentException("Rule Name cannot be empty.");
        if (rule.RequiredPatterns.Length == 0 && rule.RequiredCategories.Length == 0)
            throw new ArgumentException("Rule must have at least one pattern or category.");
        if (_rules.Count >= MaxRules)
            throw new InvalidOperationException($"Cannot exceed {MaxRules} rules.");
        if (_rules.Any(r => r.Id == rule.Id))
            throw new ArgumentException($"Duplicate rule Id: {rule.Id}");
        _rules.Add(rule);
    }

    /// <summary>
    /// Remove a rule by Id.
    /// </summary>
    public bool RemoveRule(string ruleId) =>
        _rules.RemoveAll(r => r.Id == ruleId) > 0;

    /// <summary>
    /// Get all registered rules.
    /// </summary>
    public IReadOnlyList<CorrelationRule> GetRules() => _rules.AsReadOnly();

    /// <summary>
    /// Get the number of registered rules.
    /// </summary>
    public int RuleCount => _rules.Count;

    /// <summary>
    /// Analyze a security report for correlated findings.
    /// </summary>
    public CorrelationReport Analyze(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass)
            .ToList();

        var matches = new List<CorrelationMatch>();

        foreach (var rule in _rules)
        {
            var matched = FindMatchingFindings(allFindings, rule);
            if (matched.Count > 0)
            {
                var originalMax = matched.Max(f => f.Severity);
                matches.Add(new CorrelationMatch(
                    rule, matched, originalMax, rule.AmplifiedSeverity));
            }
        }

        // Sort by amplified severity (critical first), then by match count
        matches.Sort((a, b) =>
        {
            var severityCompare = b.AmplifiedSeverity.CompareTo(a.AmplifiedSeverity);
            return severityCompare != 0 ? severityCompare : b.MatchedFindings.Count.CompareTo(a.MatchedFindings.Count);
        });

        var amplifiedCount = matches.Count(m => m.AmplifiedSeverity > m.OriginalMaxSeverity);
        var recommendations = matches.Select(m => m.Rule.Recommendation).Distinct().ToList();

        return new CorrelationReport(
            allFindings.Count,
            matches.Count,
            matches,
            amplifiedCount,
            recommendations
        );
    }

    /// <summary>
    /// Find findings that match a correlation rule.
    /// A rule matches when ALL RequiredPatterns have at least one matching finding,
    /// and ALL RequiredCategories have at least one matching finding.
    /// </summary>
    private static List<Finding> FindMatchingFindings(List<Finding> findings, CorrelationRule rule)
    {
        var matched = new HashSet<Finding>();
        bool allPatternsMatched = true;
        bool allCategoriesMatched = true;

        // Check required patterns
        foreach (var pattern in rule.RequiredPatterns)
        {
            var match = findings.FirstOrDefault(f =>
                f.Title.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                f.Description.Contains(pattern, StringComparison.OrdinalIgnoreCase));
            if (match != null)
                matched.Add(match);
            else
                allPatternsMatched = false;
        }

        // Check required categories
        foreach (var category in rule.RequiredCategories)
        {
            var match = findings.FirstOrDefault(f =>
                f.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
            if (match != null)
                matched.Add(match);
            else
                allCategoriesMatched = false;
        }

        // All conditions must be met
        if (!allPatternsMatched || !allCategoriesMatched)
            return new List<Finding>();

        return matched.ToList();
    }

    /// <summary>
    /// Built-in correlation rules for common Windows security compound risks.
    /// </summary>
    private void LoadBuiltInRules()
    {
        // Defense-in-depth failures
        _rules.Add(new CorrelationRule(
            "CORR-001", "Unprotected System",
            "Both antivirus and firewall protections are compromised.",
            new[] { "Defender", "Firewall" },
            Array.Empty<string>(),
            Severity.Critical,
            "Enable both Windows Defender and Windows Firewall immediately. The system has no perimeter or endpoint defense."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-002", "Unpatched with Disabled Defender",
            "Windows updates are not current and antivirus is disabled.",
            new[] { "Update", "Defender" },
            Array.Empty<string>(),
            Severity.Critical,
            "Apply Windows updates and enable Defender. Known vulnerabilities are exploitable with no antivirus protection."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-003", "Encryption Gap with Weak Accounts",
            "Disk encryption is not enabled and account security is weak.",
            new[] { "BitLocker", "password" },
            Array.Empty<string>(),
            Severity.Critical,
            "Enable BitLocker and enforce strong password policies. Physical access can bypass weak passwords on unencrypted disks."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-004", "No Audit Trail",
            "Event logging and system auditing are both deficient.",
            new[] { "Event Log", "audit" },
            Array.Empty<string>(),
            Severity.Warning,
            "Enable comprehensive event logging and audit policies. Security incidents cannot be investigated without audit trails."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-005", "Network Exposure",
            "Network services are exposed with insufficient firewall protection.",
            new[] { "Firewall", "SMB" },
            Array.Empty<string>(),
            Severity.Critical,
            "Restrict SMB access and tighten firewall rules. Open network services without firewall protection are a primary attack vector."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-006", "Browser Risk with No Updates",
            "Browser security issues combined with system not being updated.",
            new[] { "browser", "Update" },
            Array.Empty<string>(),
            Severity.Warning,
            "Update Windows and review browser security settings. Outdated systems with browser vulnerabilities are prime targets for drive-by attacks."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-007", "Startup Persistence Risk",
            "Unknown startup entries with process security concerns.",
            new[] { "startup", "process" },
            Array.Empty<string>(),
            Severity.Warning,
            "Review startup programs and running processes. Suspicious startup entries combined with unverified processes may indicate malware persistence."
        ));

        _rules.Add(new CorrelationRule(
            "CORR-008", "Privacy Exposure",
            "Privacy settings are weak alongside network security concerns.",
            new[] { "privacy", "network" },
            Array.Empty<string>(),
            Severity.Warning,
            "Tighten privacy settings and review network configuration. Weak privacy with network exposure increases data exfiltration risk."
        ));
    }
}
