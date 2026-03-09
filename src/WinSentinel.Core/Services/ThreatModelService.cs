using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// STRIDE-based threat modeling from audit findings. Maps findings to threat
/// categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial
/// of Service, Elevation of Privilege), identifies multi-step attack paths, and
/// generates a structured threat model with risk scoring and mitigations.
///
/// Unlike <see cref="MitreAttackMapper"/> which maps to ATT&amp;CK adversary
/// techniques, this produces design-level threat analysis following Microsoft's
/// STRIDE methodology — useful for security architecture review and threat
/// prioritization.
/// </summary>
public class ThreatModelService
{
    // ── STRIDE Categories ──────────────────────────────────────────

    /// <summary>STRIDE threat categories.</summary>
    public enum StrideCategory
    {
        /// <summary>Pretending to be someone/something else.</summary>
        Spoofing,
        /// <summary>Modifying data or code without authorization.</summary>
        Tampering,
        /// <summary>Denying having performed an action.</summary>
        Repudiation,
        /// <summary>Exposing data to unauthorized parties.</summary>
        InformationDisclosure,
        /// <summary>Preventing legitimate access to services.</summary>
        DenialOfService,
        /// <summary>Gaining higher privileges than authorized.</summary>
        ElevationOfPrivilege
    }

    // ── Result Types ───────────────────────────────────────────────

    /// <summary>A single threat identified from findings.</summary>
    public record Threat(
        string Id,
        StrideCategory Category,
        string Title,
        string Description,
        Severity RiskLevel,
        List<Finding> EvidenceFindings,
        string Mitigation,
        string? MitigationCommand
    )
    {
        /// <summary>Evidence strength (number of corroborating findings).</summary>
        public int EvidenceCount => EvidenceFindings.Count;

        /// <summary>Numeric risk score for sorting (Critical=30, Warning=10, Info=3, Pass=0).</summary>
        public int RiskScore => (int)RiskLevel * 10 + EvidenceCount;
    }

    /// <summary>A multi-step attack path combining related threats.</summary>
    public record AttackPath(
        string Id,
        string Name,
        string Narrative,
        List<AttackStep> Steps,
        Severity OverallRisk
    )
    {
        /// <summary>Number of steps in this attack path.</summary>
        public int StepCount => Steps.Count;

        /// <summary>Combined risk score across all steps.</summary>
        public int CombinedRiskScore => Steps.Sum(s => s.Threat.RiskScore);
    }

    /// <summary>A single step in an attack path.</summary>
    public record AttackStep(
        int Order,
        Threat Threat,
        string Action,
        string Prerequisite
    );

    /// <summary>Per-category summary in the threat model.</summary>
    public record CategorySummary(
        StrideCategory Category,
        int ThreatCount,
        int CriticalCount,
        int WarningCount,
        Severity WorstSeverity,
        List<string> TopMitigations
    );

    /// <summary>Full threat model report.</summary>
    public record ThreatModel(
        int TotalThreats,
        int TotalAttackPaths,
        int FindingsAnalyzed,
        Severity OverallRisk,
        List<Threat> Threats,
        List<AttackPath> AttackPaths,
        List<CategorySummary> CategorySummaries,
        List<string> PriorityActions
    )
    {
        /// <summary>STRIDE coverage — which categories have threats.</summary>
        public List<StrideCategory> AffectedCategories =>
            CategorySummaries
                .Where(c => c.ThreatCount > 0)
                .Select(c => c.Category)
                .ToList();

        /// <summary>Percentage of STRIDE categories with threats.</summary>
        public double StrideCoveragePercent =>
            Math.Round(100.0 * AffectedCategories.Count / 6, 1);
    }

    // ── Classification Rules ───────────────────────────────────────

    /// <summary>Rule mapping finding patterns to STRIDE categories.</summary>
    public record ClassificationRule(
        StrideCategory Category,
        string ThreatId,
        string ThreatTitle,
        string ThreatDescription,
        string[] FindingPatterns,
        string Mitigation,
        string? MitigationCommand = null
    );

    private readonly List<ClassificationRule> _rules = new();

    public ThreatModelService()
    {
        RegisterBuiltInRules();
    }

    /// <summary>Add a custom classification rule.</summary>
    public void AddRule(ClassificationRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _rules.Add(rule);
    }

    /// <summary>Get all registered rules.</summary>
    public IReadOnlyList<ClassificationRule> Rules => _rules.AsReadOnly();

    // ── Core Analysis ──────────────────────────────────────────────

    /// <summary>
    /// Generate a STRIDE threat model from a security report.
    /// </summary>
    public ThreatModel Analyze(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= Severity.Info)
            .ToList();

        // Step 1: Classify findings into threats
        var threats = ClassifyFindings(allFindings);

        // Step 2: Identify multi-step attack paths
        var attackPaths = IdentifyAttackPaths(threats);

        // Step 3: Build per-category summaries
        var summaries = BuildCategorySummaries(threats);

        // Step 4: Generate priority actions
        var actions = GeneratePriorityActions(threats, attackPaths);

        // Overall risk
        var overallRisk = threats.Count == 0
            ? Severity.Pass
            : threats.Max(t => t.RiskLevel);

        return new ThreatModel(
            TotalThreats: threats.Count,
            TotalAttackPaths: attackPaths.Count,
            FindingsAnalyzed: allFindings.Count,
            OverallRisk: overallRisk,
            Threats: threats.OrderByDescending(t => t.RiskScore).ToList(),
            AttackPaths: attackPaths.OrderByDescending(a => a.CombinedRiskScore).ToList(),
            CategorySummaries: summaries,
            PriorityActions: actions
        );
    }

    /// <summary>Classify findings into STRIDE threats using pattern matching.</summary>
    internal List<Threat> ClassifyFindings(List<Finding> findings)
    {
        var threats = new List<Threat>();
        var usedFindings = new HashSet<Finding>();

        foreach (var rule in _rules)
        {
            var matched = findings
                .Where(f => !usedFindings.Contains(f) && MatchesRule(f, rule))
                .ToList();

            if (matched.Count == 0) continue;

            var worstSeverity = matched.Max(f => f.Severity);

            threats.Add(new Threat(
                Id: rule.ThreatId,
                Category: rule.Category,
                Title: rule.ThreatTitle,
                Description: rule.ThreatDescription,
                RiskLevel: worstSeverity,
                EvidenceFindings: matched,
                Mitigation: rule.Mitigation,
                MitigationCommand: rule.MitigationCommand
            ));

            foreach (var f in matched) usedFindings.Add(f);
        }

        return threats;
    }

    /// <summary>Identify multi-step attack paths from threats.</summary>
    internal List<AttackPath> IdentifyAttackPaths(List<Threat> threats)
    {
        var paths = new List<AttackPath>();
        var threatMap = threats.ToDictionary(t => t.Id);

        // Built-in attack path templates
        var templates = new[]
        {
            new
            {
                Name = "Credential Theft → Privilege Escalation → Persistence",
                Steps = new[] { "T-SPOOF-01", "T-EOP-01", "T-TAMP-02" },
                Narrative = "Attacker exploits weak authentication to gain initial access, " +
                    "escalates privileges via misconfigured UAC or group policy, " +
                    "then establishes persistence by tampering with startup or scheduled tasks."
            },
            new
            {
                Name = "Information Disclosure → Lateral Movement",
                Steps = new[] { "T-INFO-01", "T-SPOOF-01", "T-EOP-01" },
                Narrative = "Exposed sensitive data (credentials, configs) enables " +
                    "identity spoofing on other systems, leading to privilege escalation " +
                    "across the environment."
            },
            new
            {
                Name = "Service Disruption → Tamper → Cover Tracks",
                Steps = new[] { "T-DOS-01", "T-TAMP-01", "T-REP-01" },
                Narrative = "Attacker disables security services to create a window, " +
                    "modifies system files or registry during the gap, " +
                    "then exploits weak audit logging to cover their tracks."
            },
            new
            {
                Name = "Firewall Bypass → Data Exfiltration",
                Steps = new[] { "T-DOS-02", "T-INFO-02", "T-REP-01" },
                Narrative = "Weak firewall rules allow unauthorized network access, " +
                    "enabling data exfiltration of sensitive system information, " +
                    "with insufficient logging to detect the breach."
            },
            new
            {
                Name = "Authentication Bypass → Full System Compromise",
                Steps = new[] { "T-SPOOF-02", "T-EOP-02", "T-TAMP-01" },
                Narrative = "Weak password policies or missing MFA allow initial compromise, " +
                    "auto-login or disabled lockout enables escalation, " +
                    "and missing integrity protections permit persistent system modification."
            }
        };

        int pathIdx = 1;
        foreach (var template in templates)
        {
            var matchedSteps = new List<AttackStep>();
            int order = 1;
            bool allPresent = true;

            foreach (var stepId in template.Steps)
            {
                if (!threatMap.TryGetValue(stepId, out var threat))
                {
                    allPresent = false;
                    break;
                }

                matchedSteps.Add(new AttackStep(
                    Order: order++,
                    Threat: threat,
                    Action: threat.Title,
                    Prerequisite: order == 2 ? "Initial access" : matchedSteps[^1].Action
                ));
            }

            // Require at least 2 of the 3 steps for a partial path
            if (matchedSteps.Count < 2) continue;

            var worstRisk = matchedSteps.Max(s => s.Threat.RiskLevel);

            paths.Add(new AttackPath(
                Id: $"AP-{pathIdx++:D3}",
                Name: allPresent ? template.Name : $"{template.Name} (partial)",
                Narrative: template.Narrative,
                Steps: matchedSteps,
                OverallRisk: worstRisk
            ));
        }

        return paths;
    }

    /// <summary>Build per-STRIDE-category summaries.</summary>
    internal List<CategorySummary> BuildCategorySummaries(List<Threat> threats)
    {
        var summaries = new List<CategorySummary>();

        foreach (StrideCategory cat in Enum.GetValues<StrideCategory>())
        {
            var catThreats = threats.Where(t => t.Category == cat).ToList();

            summaries.Add(new CategorySummary(
                Category: cat,
                ThreatCount: catThreats.Count,
                CriticalCount: catThreats.Count(t => t.RiskLevel == Severity.Critical),
                WarningCount: catThreats.Count(t => t.RiskLevel == Severity.Warning),
                WorstSeverity: catThreats.Count == 0
                    ? Severity.Pass
                    : catThreats.Max(t => t.RiskLevel),
                TopMitigations: catThreats
                    .OrderByDescending(t => t.RiskScore)
                    .Take(3)
                    .Select(t => t.Mitigation)
                    .ToList()
            ));
        }

        return summaries;
    }

    /// <summary>Generate prioritized action list.</summary>
    internal List<string> GeneratePriorityActions(
        List<Threat> threats, List<AttackPath> paths)
    {
        var actions = new List<string>();

        // Attack paths first — breaking any step breaks the chain
        foreach (var path in paths.OrderByDescending(p => p.CombinedRiskScore).Take(3))
        {
            var weakest = path.Steps
                .OrderBy(s => s.Threat.EvidenceCount)
                .First();
            actions.Add(
                $"Break attack path \"{path.Name}\" by addressing: {weakest.Threat.Title}");
        }

        // Then highest-risk individual threats not in paths
        var pathThreatIds = paths
            .SelectMany(p => p.Steps.Select(s => s.Threat.Id))
            .ToHashSet();

        foreach (var threat in threats
            .Where(t => !pathThreatIds.Contains(t.Id))
            .OrderByDescending(t => t.RiskScore)
            .Take(5))
        {
            actions.Add($"Mitigate {threat.Category}: {threat.Mitigation}");
        }

        return actions;
    }

    // ── Pattern Matching ───────────────────────────────────────────

    private static bool MatchesRule(Finding finding, ClassificationRule rule)
    {
        var title = finding.Title.ToLowerInvariant();
        var desc = finding.Description.ToLowerInvariant();
        var cat = finding.Category.ToLowerInvariant();

        return rule.FindingPatterns.Any(pattern =>
        {
            var p = pattern.ToLowerInvariant();
            return title.Contains(p) || desc.Contains(p) || cat.Contains(p);
        });
    }

    // ── Built-In Rules ─────────────────────────────────────────────

    private void RegisterBuiltInRules()
    {
        // ── Spoofing ───────────────────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Spoofing,
            ThreatId: "T-SPOOF-01",
            ThreatTitle: "Identity Spoofing via Weak Authentication",
            ThreatDescription: "Weak or missing authentication mechanisms allow " +
                "attackers to impersonate legitimate users or services.",
            FindingPatterns: new[]
            {
                "password policy", "password complexity", "password length",
                "account lockout", "guest account", "anonymous",
                "authentication", "credential"
            },
            Mitigation: "Enforce strong password policies, enable account lockout, " +
                "disable guest/anonymous access.",
            MitigationCommand: "net accounts /minpwlen:12 /lockoutthreshold:5"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Spoofing,
            ThreatId: "T-SPOOF-02",
            ThreatTitle: "Auto-Login Credential Exposure",
            ThreatDescription: "Auto-login or stored credentials in the registry " +
                "allow anyone with physical or remote access to impersonate the user.",
            FindingPatterns: new[]
            {
                "auto-login", "autologon", "DefaultPassword",
                "stored credential", "cached logon"
            },
            Mitigation: "Disable auto-login and remove stored plaintext credentials.",
            MitigationCommand: "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /f"
        ));

        // ── Tampering ──────────────────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Tampering,
            ThreatId: "T-TAMP-01",
            ThreatTitle: "System Integrity Compromise",
            ThreatDescription: "Missing integrity protections allow unauthorized " +
                "modification of system files, registry, or boot configuration.",
            FindingPatterns: new[]
            {
                "secure boot", "code integrity", "driver signing",
                "file integrity", "write permission", "registry permission",
                "bitlocker", "encryption"
            },
            Mitigation: "Enable Secure Boot, BitLocker, and code integrity policies. " +
                "Restrict write permissions on system directories.",
            MitigationCommand: "bcdedit /set {current} secureboot on"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Tampering,
            ThreatId: "T-TAMP-02",
            ThreatTitle: "Startup and Scheduled Task Manipulation",
            ThreatDescription: "Insufficient protection of startup items and " +
                "scheduled tasks allows attackers to establish persistence.",
            FindingPatterns: new[]
            {
                "startup", "scheduled task", "auto-start", "run key",
                "service permission", "persistence", "boot"
            },
            Mitigation: "Audit startup entries regularly, restrict task scheduler " +
                "permissions, and monitor for unauthorized changes."
        ));

        // ── Repudiation ────────────────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Repudiation,
            ThreatId: "T-REP-01",
            ThreatTitle: "Insufficient Audit Logging",
            ThreatDescription: "Weak or disabled audit logging makes it impossible " +
                "to attribute actions to specific users or detect intrusions.",
            FindingPatterns: new[]
            {
                "audit policy", "event log", "logging", "audit log",
                "security log", "log size", "log retention"
            },
            Mitigation: "Enable comprehensive audit policies for logon, object access, " +
                "privilege use, and policy changes.",
            MitigationCommand: "auditpol /set /category:* /success:enable /failure:enable"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.Repudiation,
            ThreatId: "T-REP-02",
            ThreatTitle: "Missing NTP Synchronization",
            ThreatDescription: "Without accurate time synchronization, log timestamps " +
                "cannot be correlated across systems, undermining forensic analysis.",
            FindingPatterns: new[]
            {
                "time sync", "ntp", "w32time", "time service",
                "clock skew"
            },
            Mitigation: "Configure Windows Time Service to sync with a reliable NTP source.",
            MitigationCommand: "w32tm /config /manualpeerlist:\"time.windows.com\" /syncfromflags:manual /reliable:YES /update"
        ));

        // ── Information Disclosure ─────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.InformationDisclosure,
            ThreatId: "T-INFO-01",
            ThreatTitle: "Sensitive Data Exposure",
            ThreatDescription: "System configuration or stored data exposes " +
                "sensitive information to unauthorized parties.",
            FindingPatterns: new[]
            {
                "share permission", "network share", "smb", "rdp",
                "remote desktop", "plaintext", "unencrypted",
                "sensitive data", "exposed"
            },
            Mitigation: "Restrict network shares, enforce SMB signing, disable " +
                "unnecessary remote access, and encrypt sensitive data.",
            MitigationCommand: "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.InformationDisclosure,
            ThreatId: "T-INFO-02",
            ThreatTitle: "Excessive System Information Leakage",
            ThreatDescription: "System exposes version info, error details, or " +
                "configuration data that aids reconnaissance.",
            FindingPatterns: new[]
            {
                "banner", "verbose error", "debug mode", "telemetry",
                "privacy", "tracking", "information disclosure",
                "last logged-on user"
            },
            Mitigation: "Suppress verbose errors, disable unnecessary telemetry, " +
                "hide last logged-on user name."
        ));

        // ── Denial of Service ──────────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.DenialOfService,
            ThreatId: "T-DOS-01",
            ThreatTitle: "Security Service Disruption",
            ThreatDescription: "Disabled or misconfigured security services leave " +
                "the system without active protection.",
            FindingPatterns: new[]
            {
                "windows defender", "antivirus", "anti-malware",
                "firewall disabled", "real-time protection",
                "windows update", "update service"
            },
            Mitigation: "Enable Windows Defender real-time protection, configure " +
                "automatic updates, and ensure firewall is active.",
            MitigationCommand: "Set-MpPreference -DisableRealtimeMonitoring $false"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.DenialOfService,
            ThreatId: "T-DOS-02",
            ThreatTitle: "Network Attack Surface",
            ThreatDescription: "Weak firewall rules or open ports create an " +
                "exploitable network attack surface.",
            FindingPatterns: new[]
            {
                "firewall rule", "open port", "inbound rule",
                "network exposure", "listening port", "unnecessary service"
            },
            Mitigation: "Review and restrict inbound firewall rules, close " +
                "unnecessary ports, disable unused services."
        ));

        // ── Elevation of Privilege ─────────────────────────────

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.ElevationOfPrivilege,
            ThreatId: "T-EOP-01",
            ThreatTitle: "Privilege Escalation via UAC/Policy Weakness",
            ThreatDescription: "Misconfigured UAC settings or group policies allow " +
                "standard users to gain administrative privileges.",
            FindingPatterns: new[]
            {
                "uac", "user account control", "admin approval",
                "privilege escalation", "elevation", "admin rights",
                "local administrator", "group policy"
            },
            Mitigation: "Set UAC to 'Always Notify', restrict local admin group " +
                "membership, enforce least-privilege policies.",
            MitigationCommand: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f"
        ));

        _rules.Add(new ClassificationRule(
            Category: StrideCategory.ElevationOfPrivilege,
            ThreatId: "T-EOP-02",
            ThreatTitle: "Uncontrolled Software Installation",
            ThreatDescription: "Missing application control policies allow " +
                "installation and execution of unauthorized software.",
            FindingPatterns: new[]
            {
                "applocker", "application control", "software restriction",
                "unsigned", "execution policy", "powershell",
                "script execution", "installer"
            },
            Mitigation: "Enable AppLocker or Windows Defender Application Control, " +
                "restrict PowerShell execution policy.",
            MitigationCommand: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
        ));
    }
}
