using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Maps security audit findings to MITRE ATT&amp;CK techniques and tactics.
/// Produces kill chain exposure reports showing which ATT&amp;CK techniques
/// an attacker could leverage based on current security posture.
/// </summary>
public class MitreAttackMapper
{
    private readonly Dictionary<string, AttackTechnique> _techniques;
    private readonly List<AttackMappingRule> _rules;

    public MitreAttackMapper()
    {
        _techniques = BuildTechniqueDatabase();
        _rules = BuildMappingRules();
    }

    /// <summary>All known technique IDs.</summary>
    public IReadOnlyList<string> TechniqueIds =>
        _techniques.Keys.OrderBy(k => k).ToList();

    /// <summary>All known tactics.</summary>
    public IReadOnlyList<AttackTactic> Tactics =>
        Enum.GetValues<AttackTactic>().ToList();

    /// <summary>Get a technique by ID.</summary>
    public AttackTechnique? GetTechnique(string techniqueId) =>
        _techniques.GetValueOrDefault(techniqueId);

    /// <summary>Get the display name for a tactic.</summary>
    public static string GetTacticName(AttackTactic tactic) => tactic switch
    {
        AttackTactic.InitialAccess => "Initial Access",
        AttackTactic.Execution => "Execution",
        AttackTactic.Persistence => "Persistence",
        AttackTactic.PrivilegeEscalation => "Privilege Escalation",
        AttackTactic.DefenseEvasion => "Defense Evasion",
        AttackTactic.CredentialAccess => "Credential Access",
        AttackTactic.Discovery => "Discovery",
        AttackTactic.LateralMovement => "Lateral Movement",
        AttackTactic.Collection => "Collection",
        AttackTactic.Exfiltration => "Exfiltration",
        AttackTactic.Impact => "Impact",
        AttackTactic.CommandAndControl => "Command and Control",
        AttackTactic.ResourceDevelopment => "Resource Development",
        AttackTactic.Reconnaissance => "Reconnaissance",
        _ => tactic.ToString()
    };

    /// <summary>
    /// Map findings from a security report to ATT&amp;CK techniques.
    /// Only Warning and Critical findings are mapped (Pass/Info are not exposures).
    /// </summary>
    public AttackReport Analyze(SecurityReport report)
    {
        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .ToList();

        var actionableFindings = allFindings
            .Where(f => f.Severity >= Severity.Warning)
            .ToList();

        var mappedPairs = new List<TechniqueFinding>();

        foreach (var finding in actionableFindings)
        {
            var matchedTechniqueIds = FindMatchingTechniques(finding);
            foreach (var techId in matchedTechniqueIds)
            {
                if (_techniques.TryGetValue(techId, out var technique))
                {
                    mappedPairs.Add(new TechniqueFinding
                    {
                        Technique = technique,
                        Finding = finding,
                        HighestSeverity = finding.Severity
                    });
                }
            }
        }

        var mappedFindingSet = mappedPairs.Select(p => p.Finding).Distinct().Count();

        // Group by tactic
        var tacticGroups = mappedPairs
            .GroupBy(p => p.Technique.Tactic)
            .OrderBy(g => (int)g.Key)
            .ToList();

        var tacticExposures = new List<TacticExposure>();
        foreach (var group in tacticGroups)
        {
            var techniques = group
                .GroupBy(p => p.Technique.Id)
                .Select(tg => new TechniqueSummary
                {
                    TechniqueId = tg.Key,
                    TechniqueName = tg.First().Technique.Name,
                    HighestSeverity = tg.Max(p => p.HighestSeverity),
                    FindingCount = tg.Select(p => p.Finding).Distinct().Count(),
                    MitreUrl = tg.First().Technique.MitreUrl
                })
                .OrderByDescending(t => t.HighestSeverity)
                .ThenByDescending(t => t.FindingCount)
                .ToList();

            var critCount = group.Count(p => p.Finding.Severity == Severity.Critical);
            var warnCount = group.Count(p => p.Finding.Severity == Severity.Warning);
            var score = ComputeExposureScore(critCount, warnCount, techniques.Count);

            tacticExposures.Add(new TacticExposure
            {
                Tactic = group.Key,
                TacticName = GetTacticName(group.Key),
                TechniqueCount = techniques.Count,
                FindingCount = group.Select(p => p.Finding).Distinct().Count(),
                CriticalCount = critCount,
                WarningCount = warnCount,
                ExposureScore = score,
                ExposureLevel = ScoreToLevel(score),
                Techniques = techniques
            });
        }

        var overallScore = tacticExposures.Count > 0
            ? tacticExposures.Average(t => t.ExposureScore)
            : 0;

        // Top techniques across all tactics
        var topTechniques = tacticExposures
            .SelectMany(t => t.Techniques)
            .OrderByDescending(t => t.HighestSeverity)
            .ThenByDescending(t => t.FindingCount)
            .Take(10)
            .ToList();

        // Kill chain heatmap
        var heatmap = new Dictionary<string, string>();
        foreach (var tactic in Enum.GetValues<AttackTactic>())
        {
            var exposure = tacticExposures.FirstOrDefault(t => t.Tactic == tactic);
            heatmap[GetTacticName(tactic)] = exposure?.ExposureLevel ?? "None";
        }

        // Generate recommendations
        var recommendations = GenerateRecommendations(tacticExposures, topTechniques);

        return new AttackReport
        {
            TotalFindings = allFindings.Count,
            MappedFindings = mappedFindingSet,
            UnmappedFindings = actionableFindings.Count - mappedFindingSet,
            CoveragePercent = actionableFindings.Count > 0
                ? Math.Round(100.0 * mappedFindingSet / actionableFindings.Count, 1)
                : 100,
            TechniquesExposed = topTechniques.Count > 0
                ? tacticExposures.Sum(t => t.TechniqueCount)
                : 0,
            TacticsExposed = tacticExposures.Count,
            OverallExposureScore = Math.Round(overallScore, 1),
            OverallExposureLevel = ScoreToLevel(overallScore),
            TacticExposures = tacticExposures,
            TopTechniques = topTechniques,
            Recommendations = recommendations,
            KillChainHeatmap = heatmap
        };
    }

    /// <summary>
    /// Map a single finding to matching technique IDs.
    /// </summary>
    public List<string> MapFinding(Finding finding)
    {
        return FindMatchingTechniques(finding);
    }

    /// <summary>
    /// Get all techniques for a specific tactic.
    /// </summary>
    public List<AttackTechnique> GetTechniquesForTactic(AttackTactic tactic) =>
        _techniques.Values
            .Where(t => t.Tactic == tactic)
            .OrderBy(t => t.Id)
            .ToList();

    /// <summary>
    /// Generate a text report.
    /// </summary>
    public string FormatReport(AttackReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("══════════════════════════════════════════════════════");
        sb.AppendLine("         MITRE ATT&CK EXPOSURE REPORT");
        sb.AppendLine("══════════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"  Generated:       {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Overall Level:   {report.OverallExposureLevel} ({report.OverallExposureScore}/100)");
        sb.AppendLine($"  Tactics Exposed: {report.TacticsExposed} / {Enum.GetValues<AttackTactic>().Length}");
        sb.AppendLine($"  Techniques:      {report.TechniquesExposed}");
        sb.AppendLine($"  Mapped Findings: {report.MappedFindings} / {report.TotalFindings}");
        sb.AppendLine($"  Coverage:        {report.CoveragePercent}%");
        sb.AppendLine();

        // Kill chain heatmap
        sb.AppendLine("── Kill Chain Heatmap ──────────────────────────────");
        foreach (var (tactic, level) in report.KillChainHeatmap)
        {
            var indicator = level switch
            {
                "Critical" => "████",
                "High" => "███░",
                "Medium" => "██░░",
                "Low" => "█░░░",
                _ => "░░░░"
            };
            sb.AppendLine($"  {indicator}  {tactic,-24} {level}");
        }
        sb.AppendLine();

        // Per-tactic detail
        foreach (var tactic in report.TacticExposures)
        {
            sb.AppendLine($"── {tactic.TacticName} ── Score: {tactic.ExposureScore} ({tactic.ExposureLevel}) ──");
            foreach (var tech in tactic.Techniques)
            {
                var sev = tech.HighestSeverity == Severity.Critical ? "!!" : "! ";
                sb.AppendLine($"  {sev} {tech.TechniqueId,-10} {tech.TechniqueName,-35} [{tech.FindingCount} finding(s)]");
            }
            sb.AppendLine();
        }

        // Top techniques
        if (report.TopTechniques.Count > 0)
        {
            sb.AppendLine("── Top Exposed Techniques ─────────────────────────");
            for (var i = 0; i < report.TopTechniques.Count; i++)
            {
                var tech = report.TopTechniques[i];
                sb.AppendLine($"  {i + 1}. {tech.TechniqueId} - {tech.TechniqueName} ({tech.FindingCount} findings, {tech.HighestSeverity})");
            }
            sb.AppendLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            sb.AppendLine("── Recommendations ────────────────────────────────");
            foreach (var rec in report.Recommendations)
            {
                sb.AppendLine($"  → {rec}");
            }
        }

        return sb.ToString();
    }

    #region Private Methods

    private List<string> FindMatchingTechniques(Finding finding)
    {
        var matched = new HashSet<string>();

        foreach (var rule in _rules)
        {
            var categoryMatch = rule.CategoryPatterns.Count == 0 ||
                rule.CategoryPatterns.Any(p =>
                    finding.Category.Contains(p, StringComparison.OrdinalIgnoreCase));

            var titleMatch = rule.TitlePatterns.Count == 0 ||
                rule.TitlePatterns.Any(p =>
                    finding.Title.Contains(p, StringComparison.OrdinalIgnoreCase));

            var descMatch = rule.DescriptionPatterns.Count == 0 ||
                rule.DescriptionPatterns.Any(p =>
                    (finding.Description ?? "").Contains(p, StringComparison.OrdinalIgnoreCase));

            // Must match at least one non-empty pattern set
            var hasPatterns = rule.CategoryPatterns.Count > 0 ||
                             rule.TitlePatterns.Count > 0 ||
                             rule.DescriptionPatterns.Count > 0;

            if (hasPatterns && categoryMatch && titleMatch && descMatch)
            {
                matched.Add(rule.TechniqueId);
            }
        }

        return matched.ToList();
    }

    private static double ComputeExposureScore(int criticals, int warnings, int techniqueCount)
    {
        // Weighted score: criticals count more
        var rawScore = (criticals * 25.0) + (warnings * 10.0) + (techniqueCount * 5.0);
        return Math.Min(100, Math.Round(rawScore, 1));
    }

    private static string ScoreToLevel(double score) => score switch
    {
        >= 75 => "Critical",
        >= 50 => "High",
        >= 25 => "Medium",
        > 0 => "Low",
        _ => "None"
    };

    private static List<string> GenerateRecommendations(
        List<TacticExposure> tactics, List<TechniqueSummary> topTechniques)
    {
        var recs = new List<string>();

        var criticalTactics = tactics.Where(t => t.ExposureLevel == "Critical").ToList();
        if (criticalTactics.Count > 0)
        {
            recs.Add($"URGENT: {criticalTactics.Count} tactic(s) at Critical exposure — " +
                     string.Join(", ", criticalTactics.Select(t => t.TacticName)));
        }

        if (tactics.Any(t => t.Tactic == AttackTactic.InitialAccess && t.ExposureScore > 25))
            recs.Add("Harden initial access vectors: review firewall rules, exposed services, and remote access");

        if (tactics.Any(t => t.Tactic == AttackTactic.CredentialAccess && t.ExposureScore > 25))
            recs.Add("Strengthen credential security: enforce password policies, enable MFA, review stored credentials");

        if (tactics.Any(t => t.Tactic == AttackTactic.Persistence && t.ExposureScore > 25))
            recs.Add("Review persistence mechanisms: audit startup items, scheduled tasks, registry run keys");

        if (tactics.Any(t => t.Tactic == AttackTactic.PrivilegeEscalation && t.ExposureScore > 25))
            recs.Add("Reduce privilege escalation risk: apply least-privilege, review UAC settings, patch vulnerabilities");

        if (tactics.Any(t => t.Tactic == AttackTactic.LateralMovement && t.ExposureScore > 25))
            recs.Add("Limit lateral movement: segment networks, disable unnecessary remote protocols (RDP, SMB, WinRM)");

        if (tactics.Any(t => t.Tactic == AttackTactic.Exfiltration && t.ExposureScore > 25))
            recs.Add("Prevent data exfiltration: enable encryption, audit clipboard/USB policies, monitor outbound traffic");

        if (tactics.Any(t => t.Tactic == AttackTactic.DefenseEvasion && t.ExposureScore > 25))
            recs.Add("Address defense evasion: verify antivirus is active, audit PowerShell policies, check logging gaps");

        var topCritical = topTechniques
            .Where(t => t.HighestSeverity == Severity.Critical)
            .Take(3)
            .ToList();
        if (topCritical.Count > 0)
        {
            recs.Add("Priority remediation: " +
                     string.Join("; ", topCritical.Select(t => $"{t.TechniqueId} ({t.TechniqueName})")));
        }

        if (recs.Count == 0)
            recs.Add("Exposure is minimal — continue monitoring and maintain current security posture");

        return recs;
    }

    private static Dictionary<string, AttackTechnique> BuildTechniqueDatabase()
    {
        var techniques = new AttackTechnique[]
        {
            // Initial Access
            new() { Id = "T1133", Name = "External Remote Services", Tactic = AttackTactic.InitialAccess,
                Description = "Adversaries may leverage external-facing remote services to initially access a network" },
            new() { Id = "T1078", Name = "Valid Accounts", Tactic = AttackTactic.InitialAccess,
                Description = "Adversaries may obtain and abuse credentials of existing accounts" },
            new() { Id = "T1190", Name = "Exploit Public-Facing Application", Tactic = AttackTactic.InitialAccess,
                Description = "Adversaries may exploit vulnerabilities in internet-facing software" },
            new() { Id = "T1566", Name = "Phishing", Tactic = AttackTactic.InitialAccess,
                Description = "Adversaries may send phishing messages to gain access" },

            // Execution
            new() { Id = "T1059", Name = "Command and Scripting Interpreter", Tactic = AttackTactic.Execution,
                Description = "Adversaries may abuse command and script interpreters to execute commands" },
            new() { Id = "T1059.001", Name = "PowerShell", Tactic = AttackTactic.Execution,
                Description = "Adversaries may abuse PowerShell for execution" },
            new() { Id = "T1053", Name = "Scheduled Task/Job", Tactic = AttackTactic.Execution,
                Description = "Adversaries may abuse task scheduling to execute malicious code" },
            new() { Id = "T1204", Name = "User Execution", Tactic = AttackTactic.Execution,
                Description = "Adversary relies on user running a malicious file" },

            // Persistence
            new() { Id = "T1547", Name = "Boot or Logon Autostart Execution", Tactic = AttackTactic.Persistence,
                Description = "Adversaries may configure system settings to automatically execute at startup" },
            new() { Id = "T1547.001", Name = "Registry Run Keys", Tactic = AttackTactic.Persistence,
                Description = "Adversaries may achieve persistence via registry run keys" },
            new() { Id = "T1543", Name = "Create or Modify System Process", Tactic = AttackTactic.Persistence,
                Description = "Adversaries may create or modify system processes to repeatedly execute" },
            new() { Id = "T1136", Name = "Create Account", Tactic = AttackTactic.Persistence,
                Description = "Adversaries may create accounts to maintain access" },

            // Privilege Escalation
            new() { Id = "T1548", Name = "Abuse Elevation Control", Tactic = AttackTactic.PrivilegeEscalation,
                Description = "Adversaries may circumvent UAC or elevation controls" },
            new() { Id = "T1134", Name = "Access Token Manipulation", Tactic = AttackTactic.PrivilegeEscalation,
                Description = "Adversaries may modify access tokens to operate under different security contexts" },
            new() { Id = "T1068", Name = "Exploitation for Privilege Escalation", Tactic = AttackTactic.PrivilegeEscalation,
                Description = "Adversaries may exploit software vulnerabilities to elevate privileges" },

            // Defense Evasion
            new() { Id = "T1562", Name = "Impair Defenses", Tactic = AttackTactic.DefenseEvasion,
                Description = "Adversaries may disable security tools to avoid detection" },
            new() { Id = "T1562.001", Name = "Disable or Modify Tools", Tactic = AttackTactic.DefenseEvasion,
                Description = "Adversaries may disable antivirus or security tools" },
            new() { Id = "T1070", Name = "Indicator Removal", Tactic = AttackTactic.DefenseEvasion,
                Description = "Adversaries may delete or modify artifacts to remove evidence" },
            new() { Id = "T1112", Name = "Modify Registry", Tactic = AttackTactic.DefenseEvasion,
                Description = "Adversaries may modify the registry to hide configuration or evade detection" },
            new() { Id = "T1027", Name = "Obfuscated Files or Information", Tactic = AttackTactic.DefenseEvasion,
                Description = "Adversaries may obfuscate content to make detection harder" },

            // Credential Access
            new() { Id = "T1003", Name = "OS Credential Dumping", Tactic = AttackTactic.CredentialAccess,
                Description = "Adversaries may dump credentials from the OS" },
            new() { Id = "T1110", Name = "Brute Force", Tactic = AttackTactic.CredentialAccess,
                Description = "Adversaries may brute force credentials" },
            new() { Id = "T1555", Name = "Credentials from Password Stores", Tactic = AttackTactic.CredentialAccess,
                Description = "Adversaries may search for credentials in password stores" },
            new() { Id = "T1552", Name = "Unsecured Credentials", Tactic = AttackTactic.CredentialAccess,
                Description = "Adversaries may search for unsecured credentials in files, registry, etc." },

            // Discovery
            new() { Id = "T1082", Name = "System Information Discovery", Tactic = AttackTactic.Discovery,
                Description = "Adversaries may gather detailed system information" },
            new() { Id = "T1083", Name = "File and Directory Discovery", Tactic = AttackTactic.Discovery,
                Description = "Adversaries may enumerate files and directories" },
            new() { Id = "T1135", Name = "Network Share Discovery", Tactic = AttackTactic.Discovery,
                Description = "Adversaries may look for shared folders and drives" },
            new() { Id = "T1046", Name = "Network Service Discovery", Tactic = AttackTactic.Discovery,
                Description = "Adversaries may scan for services running on remote hosts" },

            // Lateral Movement
            new() { Id = "T1021", Name = "Remote Services", Tactic = AttackTactic.LateralMovement,
                Description = "Adversaries may use remote services (RDP, SSH, SMB) to move laterally" },
            new() { Id = "T1021.001", Name = "Remote Desktop Protocol", Tactic = AttackTactic.LateralMovement,
                Description = "Adversaries may use RDP to log into remote systems" },
            new() { Id = "T1021.002", Name = "SMB/Windows Admin Shares", Tactic = AttackTactic.LateralMovement,
                Description = "Adversaries may use SMB to interact with remote shares" },
            new() { Id = "T1570", Name = "Lateral Tool Transfer", Tactic = AttackTactic.LateralMovement,
                Description = "Adversaries may transfer tools between systems within a network" },

            // Collection
            new() { Id = "T1115", Name = "Clipboard Data", Tactic = AttackTactic.Collection,
                Description = "Adversaries may collect data stored in the clipboard" },
            new() { Id = "T1005", Name = "Data from Local System", Tactic = AttackTactic.Collection,
                Description = "Adversaries may search local system sources for data" },
            new() { Id = "T1039", Name = "Data from Network Shared Drive", Tactic = AttackTactic.Collection,
                Description = "Adversaries may search network shares for data" },

            // Exfiltration
            new() { Id = "T1048", Name = "Exfiltration Over Alternative Protocol", Tactic = AttackTactic.Exfiltration,
                Description = "Adversaries may steal data by exfiltrating over different protocols" },
            new() { Id = "T1041", Name = "Exfiltration Over C2 Channel", Tactic = AttackTactic.Exfiltration,
                Description = "Adversaries may steal data by sending it over C2" },
            new() { Id = "T1052", Name = "Exfiltration Over Physical Medium", Tactic = AttackTactic.Exfiltration,
                Description = "Adversaries may attempt to exfiltrate data via USB or other physical media" },

            // Impact
            new() { Id = "T1486", Name = "Data Encrypted for Impact", Tactic = AttackTactic.Impact,
                Description = "Adversaries may encrypt data on target systems (ransomware)" },
            new() { Id = "T1490", Name = "Inhibit System Recovery", Tactic = AttackTactic.Impact,
                Description = "Adversaries may delete or disable system recovery features" },
            new() { Id = "T1489", Name = "Service Stop", Tactic = AttackTactic.Impact,
                Description = "Adversaries may stop or disable services" },

            // Command and Control
            new() { Id = "T1071", Name = "Application Layer Protocol", Tactic = AttackTactic.CommandAndControl,
                Description = "Adversaries may communicate using application layer protocols (HTTP, DNS)" },
            new() { Id = "T1105", Name = "Ingress Tool Transfer", Tactic = AttackTactic.CommandAndControl,
                Description = "Adversaries may transfer tools from an external system" },
            new() { Id = "T1572", Name = "Protocol Tunneling", Tactic = AttackTactic.CommandAndControl,
                Description = "Adversaries may tunnel C2 traffic through legitimate protocols" },
        };

        return techniques.ToDictionary(t => t.Id, StringComparer.OrdinalIgnoreCase);
    }

    private static List<AttackMappingRule> BuildMappingRules()
    {
        return new List<AttackMappingRule>
        {
            // Initial Access
            new() { TechniqueId = "T1133", CategoryPatterns = { "RemoteAccess", "RDP", "SSH", "WinRM" } },
            new() { TechniqueId = "T1078", CategoryPatterns = { "Accounts", "Credentials" },
                TitlePatterns = { "guest", "default", "password", "weak", "blank" } },
            new() { TechniqueId = "T1190", CategoryPatterns = { "Software", "Updates" },
                TitlePatterns = { "vulnerable", "outdated", "unpatched", "exploit" } },

            // Execution
            new() { TechniqueId = "T1059.001", CategoryPatterns = { "PowerShell" } },
            new() { TechniqueId = "T1059", CategoryPatterns = { "PowerShell", "Script" },
                TitlePatterns = { "script", "execution policy", "macro" } },
            new() { TechniqueId = "T1053", CategoryPatterns = { "ScheduledTasks" } },

            // Persistence
            new() { TechniqueId = "T1547.001", CategoryPatterns = { "Startup", "Registry" },
                TitlePatterns = { "run key", "autostart", "startup" } },
            new() { TechniqueId = "T1547", CategoryPatterns = { "Startup" } },
            new() { TechniqueId = "T1543", TitlePatterns = { "service", "daemon" },
                CategoryPatterns = { "Services" } },
            new() { TechniqueId = "T1136", CategoryPatterns = { "Accounts" },
                TitlePatterns = { "guest account", "unauthorized account" } },

            // Privilege Escalation
            new() { TechniqueId = "T1548", CategoryPatterns = { "UAC", "Privilege" },
                TitlePatterns = { "UAC", "elevation", "admin" } },
            new() { TechniqueId = "T1068", CategoryPatterns = { "Updates", "Software" },
                TitlePatterns = { "patch", "CVE", "vulnerability" } },

            // Defense Evasion
            new() { TechniqueId = "T1562.001", TitlePatterns = { "antivirus", "defender", "firewall disabled", "security disabled" } },
            new() { TechniqueId = "T1562", CategoryPatterns = { "Firewall" },
                TitlePatterns = { "disabled", "off", "inactive" } },
            new() { TechniqueId = "T1070", TitlePatterns = { "logging", "audit log", "event log" },
                DescriptionPatterns = { "log", "audit trail" } },
            new() { TechniqueId = "T1112", CategoryPatterns = { "Registry" } },

            // Credential Access
            new() { TechniqueId = "T1110", CategoryPatterns = { "Accounts", "Credentials" },
                TitlePatterns = { "lockout", "brute", "password policy", "password length" } },
            new() { TechniqueId = "T1552", CategoryPatterns = { "Credentials", "Privacy" },
                TitlePatterns = { "stored", "plaintext", "unencrypted", "cleartext" } },
            new() { TechniqueId = "T1555", TitlePatterns = { "password store", "credential manager", "browser password" } },
            new() { TechniqueId = "T1003", TitlePatterns = { "credential dump", "LSASS", "SAM", "NTDS" } },

            // Discovery
            new() { TechniqueId = "T1135", CategoryPatterns = { "SMB", "Network" },
                TitlePatterns = { "share", "SMB" } },
            new() { TechniqueId = "T1046", CategoryPatterns = { "Firewall", "Network" },
                TitlePatterns = { "open port", "exposed service", "listening" } },

            // Lateral Movement
            new() { TechniqueId = "T1021.001", CategoryPatterns = { "RDP", "RemoteAccess" },
                TitlePatterns = { "RDP", "Remote Desktop" } },
            new() { TechniqueId = "T1021.002", CategoryPatterns = { "SMB" },
                TitlePatterns = { "SMB", "admin share" } },
            new() { TechniqueId = "T1021", CategoryPatterns = { "RemoteAccess", "WinRM", "SSH" } },

            // Collection
            new() { TechniqueId = "T1115", CategoryPatterns = { "Clipboard", "Privacy" },
                TitlePatterns = { "clipboard" } },
            new() { TechniqueId = "T1005", CategoryPatterns = { "Encryption", "Privacy" },
                TitlePatterns = { "unencrypted", "BitLocker", "encryption" } },

            // Exfiltration
            new() { TechniqueId = "T1052", CategoryPatterns = { "USB", "Bluetooth" },
                TitlePatterns = { "USB", "removable", "external" } },
            new() { TechniqueId = "T1048", CategoryPatterns = { "DNS", "Network" },
                TitlePatterns = { "DNS", "tunnel", "exfil" } },

            // Impact
            new() { TechniqueId = "T1486", CategoryPatterns = { "Encryption", "Backup" },
                TitlePatterns = { "ransomware", "encryption" } },
            new() { TechniqueId = "T1490", CategoryPatterns = { "Backup" },
                TitlePatterns = { "recovery", "backup", "restore point", "shadow copy" } },

            // C2
            new() { TechniqueId = "T1071", CategoryPatterns = { "Firewall", "Network" },
                TitlePatterns = { "outbound", "HTTP", "DNS" } },
            new() { TechniqueId = "T1572", CategoryPatterns = { "Network" },
                TitlePatterns = { "tunnel", "proxy", "VPN" } },
        };
    }

    #endregion
}
