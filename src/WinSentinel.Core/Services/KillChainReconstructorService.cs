namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Kill Chain Reconstructor — maps security audit findings to MITRE ATT&amp;CK
/// kill chain phases, detects multi-phase attack progressions, predicts next likely phases,
/// and generates prioritized response plans. Enables defenders to see the "big picture" of
/// an attack in progress rather than isolated findings.
///
/// Kill chain phases (Lockheed Martin Cyber Kill Chain mapped to MITRE ATT&amp;CK Tactics):
///   0. Reconnaissance (TA0043)
///   1. Resource Development (TA0042)
///   2. Initial Access (TA0001)
///   3. Execution (TA0002)
///   4. Persistence (TA0003)
///   5. Privilege Escalation (TA0004)
///   6. Defense Evasion (TA0005)
///   7. Credential Access (TA0006)
///   8. Discovery (TA0007)
///   9. Lateral Movement (TA0008)
///  10. Collection (TA0009)
///  11. Command &amp; Control (TA0011)
///  12. Exfiltration (TA0010)
///  13. Impact (TA0040)
/// </summary>
public sealed class KillChainReconstructorService
{
    /// <summary>
    /// Kill chain phase definitions.
    /// </summary>
    public static readonly KillChainPhaseDef[] PhaseDefinitions =
    [
        new("Reconnaissance", "TA0043", 0),
        new("Resource Development", "TA0042", 1),
        new("Initial Access", "TA0001", 2),
        new("Execution", "TA0002", 3),
        new("Persistence", "TA0003", 4),
        new("Privilege Escalation", "TA0004", 5),
        new("Defense Evasion", "TA0005", 6),
        new("Credential Access", "TA0006", 7),
        new("Discovery", "TA0007", 8),
        new("Lateral Movement", "TA0008", 9),
        new("Collection", "TA0009", 10),
        new("Command & Control", "TA0011", 11),
        new("Exfiltration", "TA0010", 12),
        new("Impact", "TA0040", 13),
    ];

    /// <summary>
    /// Maps finding categories and title keywords to kill chain phases.
    /// Key = phase index, Value = list of (category pattern, title keywords) matchers.
    /// </summary>
    private static readonly Dictionary<int, List<PhaseMapping>> PhaseMappings = new()
    {
        [0] = // Reconnaissance
        [
            new("Network", ["scan", "enumeration", "discovery", "exposed port", "open port", "service exposed"]),
            new("DNS", ["zone transfer", "dns record", "subdomain"]),
            new("System", ["information disclosure", "version exposed"]),
        ],
        [1] = // Resource Development
        [
            new("Certificate", ["untrusted", "expired", "self-signed", "root certificate"]),
            new("Software", ["outdated", "vulnerable version", "unpatched"]),
        ],
        [2] = // Initial Access
        [
            new("RemoteAccess", ["rdp", "ssh", "remote desktop", "vnc", "enabled"]),
            new("Network", ["smb", "telnet", "ftp accessible"]),
            new("Browser", ["phishing", "download", "unsafe"]),
            new("Wifi", ["open network", "weak encryption", "wep"]),
            new("Firewall", ["inbound", "allow all", "any any", "disabled"]),
        ],
        [3] = // Execution
        [
            new("PowerShell", ["unrestricted", "bypass", "execution policy", "script"]),
            new("ScheduledTask", ["suspicious", "unknown", "unrecognized"]),
            new("Process", ["injection", "hollowing", "suspicious process"]),
            new("AppSecurity", ["macro", "unsigned", "untrusted"]),
        ],
        [4] = // Persistence
        [
            new("Startup", ["run key", "startup", "autorun", "boot"]),
            new("ScheduledTask", ["persistence", "scheduled", "new task"]),
            new("Service", ["new service", "modified service", "unsigned service"]),
            new("Registry", ["run key", "persistence", "autostart"]),
        ],
        [5] = // Privilege Escalation
        [
            new("Account", ["admin", "privilege", "elevated", "uac disabled", "local admin"]),
            new("Driver", ["vulnerable driver", "unsigned driver", "kernel"]),
            new("Service", ["unquoted path", "weak permissions", "writable"]),
            new("GroupPolicy", ["gpo", "privilege", "elevation"]),
        ],
        [6] = // Defense Evasion
        [
            new("Defender", ["disabled", "tamper", "exclusion", "real-time off"]),
            new("EventLog", ["cleared", "disabled", "modified", "audit policy"]),
            new("Firewall", ["disabled", "rule deleted", "bypass"]),
            new("Virtualization", ["sandbox", "evasion", "detection"]),
        ],
        [7] = // Credential Access
        [
            new("Credential", ["dump", "lsass", "mimikatz", "stored password", "plain text"]),
            new("Account", ["weak password", "no password", "password policy"]),
            new("Browser", ["saved password", "credential store", "autofill"]),
            new("Clipboard", ["clipboard", "keylog"]),
        ],
        [8] = // Discovery
        [
            new("System", ["system info", "discovery", "whoami", "hostname"]),
            new("Network", ["arp", "netstat", "network discovery", "neighbor"]),
            new("FileSystem", ["directory listing", "file discovery", "enumeration"]),
            new("Account", ["account enumeration", "user list"]),
        ],
        [9] = // Lateral Movement
        [
            new("SMB", ["admin share", "remote", "lateral", "psexec"]),
            new("RemoteAccess", ["rdp session", "lateral", "pass the hash"]),
            new("Network", ["internal pivot", "lateral movement"]),
        ],
        [10] = // Collection
        [
            new("Privacy", ["data collection", "telemetry", "clipboard", "screen capture"]),
            new("Clipboard", ["clipboard", "monitoring"]),
            new("FileSystem", ["staged", "archive", "compressed"]),
        ],
        [11] = // Command & Control
        [
            new("Network", ["beacon", "callback", "c2", "command and control", "unusual dns"]),
            new("DNS", ["tunneling", "dga", "fast-flux"]),
            new("Bluetooth", ["unauthorized", "unknown device"]),
            new("Firewall", ["outbound", "suspicious connection"]),
        ],
        [12] = // Exfiltration
        [
            new("Network", ["exfiltration", "data transfer", "upload", "outbound spike"]),
            new("Bluetooth", ["file transfer", "obex"]),
            new("DNS", ["dns exfil", "encoded"]),
        ],
        [13] = // Impact
        [
            new("Backup", ["backup disabled", "shadow copy", "recovery disabled", "no backup"]),
            new("Encryption", ["ransomware", "encrypted", "bitlocker"]),
            new("Service", ["stopped", "crashed", "denial"]),
            new("Update", ["pending updates", "critical patch", "end of life"]),
        ],
    };

    /// <summary>
    /// Known attack progressions — sequences of phases that indicate specific attack patterns.
    /// </summary>
    private static readonly AttackProgressionTemplate[] ProgressionTemplates =
    [
        new("Ransomware Campaign", "Classic ransomware progression: initial access → execution → defense evasion → impact",
            [2, 3, 6, 13], "Critical"),
        new("Credential Theft Operation", "Focused credential harvesting: initial access → privilege escalation → credential access → exfiltration",
            [2, 5, 7, 12], "High"),
        new("APT Intrusion", "Advanced persistent threat: reconnaissance → initial access → persistence → discovery → lateral movement",
            [0, 2, 4, 8, 9], "Critical"),
        new("Insider Threat", "Internal malicious activity: discovery → collection → exfiltration",
            [8, 10, 12], "High"),
        new("Supply Chain Attack", "Compromise via trusted software: resource development → initial access → execution → persistence",
            [1, 2, 3, 4], "Critical"),
        new("Privilege Escalation Chain", "Escalation to domain admin: execution → privilege escalation → credential access → lateral movement",
            [3, 5, 7, 9], "High"),
        new("Defense Neutralization", "Blinding security tools before attacking: defense evasion → credential access → lateral movement → impact",
            [6, 7, 9, 13], "Critical"),
        new("Data Staging & Exfil", "Preparing data for theft: discovery → collection → command & control → exfiltration",
            [8, 10, 11, 12], "High"),
        new("Persistence Establishment", "Gaining long-term foothold: initial access → execution → persistence → privilege escalation",
            [2, 3, 4, 5], "Medium"),
        new("Reconnaissance to Breach", "Targeted penetration: reconnaissance → resource development → initial access → execution",
            [0, 1, 2, 3], "Medium"),
    ];

    /// <summary>
    /// Phase transition probabilities — what phases typically follow active phases.
    /// Key = active phase index, Values = (next phase index, base probability).
    /// </summary>
    private static readonly Dictionary<int, List<(int nextPhase, int baseProbability)>> TransitionProbabilities = new()
    {
        [0] = [(1, 70), (2, 60)],
        [1] = [(2, 80)],
        [2] = [(3, 85), (4, 60)],
        [3] = [(4, 75), (5, 65), (6, 50)],
        [4] = [(5, 60), (6, 55), (8, 40)],
        [5] = [(6, 70), (7, 75), (8, 50)],
        [6] = [(7, 65), (3, 50)],
        [7] = [(9, 80), (8, 45)],
        [8] = [(9, 70), (10, 55)],
        [9] = [(7, 50), (10, 65), (4, 40)],
        [10] = [(11, 70), (12, 60)],
        [11] = [(12, 80), (10, 40)],
        [12] = [(13, 45)],
        [13] = [],
    };

    /// <summary>
    /// Reconstructs the kill chain state from a set of security findings.
    /// </summary>
    public KillChainReport Reconstruct(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var report = new KillChainReport();
        var phaseFindings = new Dictionary<int, List<Finding>>();

        // Map findings to kill chain phases
        int unmapped = 0;
        foreach (var finding in findings)
        {
            if (finding.Severity == Severity.Pass) continue;

            var mapped = false;
            foreach (var (phaseIdx, mappings) in PhaseMappings)
            {
                foreach (var mapping in mappings)
                {
                    if (MatchesPhase(finding, mapping))
                    {
                        if (!phaseFindings.ContainsKey(phaseIdx))
                            phaseFindings[phaseIdx] = [];
                        phaseFindings[phaseIdx].Add(finding);
                        mapped = true;
                        break;
                    }
                }
                if (mapped) break;
            }
            if (!mapped) unmapped++;
        }

        report.UnmappedFindingCount = unmapped;
        report.MappedFindingCount = phaseFindings.Values.Sum(f => f.Count);

        // Build per-phase results
        foreach (var phaseDef in PhaseDefinitions)
        {
            var hasFindings = phaseFindings.TryGetValue(phaseDef.Index, out var pf);
            var phaseResult = new KillChainPhaseResult
            {
                Phase = phaseDef.Name,
                PhaseIndex = phaseDef.Index,
                TacticId = phaseDef.TacticId,
                IsActive = hasFindings && pf!.Count > 0,
                FindingCount = hasFindings ? pf!.Count : 0,
                MaxSeverity = hasFindings ? MaxSev(pf!) : "None",
                ObservedTechniques = hasFindings ? ExtractTechniques(pf!, phaseDef.Index) : [],
                FindingTitles = hasFindings ? pf!.Select(f => f.Title).Distinct().Take(10).ToList() : [],
            };
            report.Phases.Add(phaseResult);
        }

        report.ActivePhaseCount = report.Phases.Count(p => p.IsActive);
        report.CoverageScore = (int)(report.ActivePhaseCount / (double)PhaseDefinitions.Length * 100);

        // Detect attack progressions
        var activePhaseIndices = new HashSet<int>(report.Phases.Where(p => p.IsActive).Select(p => p.PhaseIndex));
        report.Progressions = DetectProgressions(activePhaseIndices);

        // Predict next phases
        report.Predictions = PredictNextPhases(activePhaseIndices);

        // Generate response plan
        report.ResponsePlan = GenerateResponsePlan(report.Phases, report.Predictions);

        // Determine overall threat level
        report.ThreatLevel = ClassifyThreatLevel(report);

        // Generate narrative
        report.Narrative = GenerateNarrative(report);

        return report;
    }

    private static bool MatchesPhase(Finding finding, PhaseMapping mapping)
    {
        // Category must match (case-insensitive substring)
        if (!finding.Category.Contains(mapping.Category, StringComparison.OrdinalIgnoreCase))
            return false;

        // At least one keyword must match in title or description
        var text = $"{finding.Title} {finding.Description}";
        return mapping.Keywords.Any(kw => text.Contains(kw, StringComparison.OrdinalIgnoreCase));
    }

    private static string MaxSev(List<Finding> findings)
    {
        if (findings.Any(f => f.Severity == Severity.Critical)) return "Critical";
        if (findings.Any(f => f.Severity == Severity.Warning)) return "Warning";
        if (findings.Any(f => f.Severity == Severity.Info)) return "Info";
        return "None";
    }

    private static List<string> ExtractTechniques(List<Finding> findings, int phaseIndex)
    {
        var techniques = new HashSet<string>();
        if (!PhaseMappings.TryGetValue(phaseIndex, out var mappings)) return [];

        foreach (var finding in findings)
        {
            foreach (var mapping in mappings)
            {
                if (MatchesPhase(finding, mapping))
                {
                    techniques.Add($"{mapping.Category}: {string.Join("/", mapping.Keywords.Where(k =>
                        $"{finding.Title} {finding.Description}".Contains(k, StringComparison.OrdinalIgnoreCase)).Take(2))}");
                }
            }
        }

        return techniques.Take(8).ToList();
    }

    private static List<AttackProgression> DetectProgressions(HashSet<int> activePhases)
    {
        var results = new List<AttackProgression>();

        foreach (var template in ProgressionTemplates)
        {
            var matchedPhases = template.RequiredPhases.Where(activePhases.Contains).ToList();
            if (matchedPhases.Count < 2) continue;

            var confidence = (int)(matchedPhases.Count / (double)template.RequiredPhases.Length * 100);
            if (confidence < 40) continue;

            results.Add(new AttackProgression
            {
                Name = template.Name,
                Description = template.Description,
                Phases = matchedPhases.Select(i => PhaseDefinitions[i].Name).ToList(),
                Confidence = confidence,
                Severity = confidence >= 75 ? template.Severity : DowngradeSeverity(template.Severity),
                Techniques = matchedPhases.SelectMany(i =>
                    PhaseMappings.GetValueOrDefault(i, [])
                        .Select(m => $"{PhaseDefinitions[i].TacticId}: {m.Category}"))
                    .Take(6).ToList(),
            });
        }

        return results.OrderByDescending(p => p.Confidence).Take(5).ToList();
    }

    private static string DowngradeSeverity(string severity) => severity switch
    {
        "Critical" => "High",
        "High" => "Medium",
        "Medium" => "Low",
        _ => "Low"
    };

    private static List<PhasePrediction> PredictNextPhases(HashSet<int> activePhases)
    {
        var predictions = new Dictionary<int, (int probability, List<string> reasons)>();

        foreach (var activePhase in activePhases)
        {
            if (!TransitionProbabilities.TryGetValue(activePhase, out var transitions)) continue;

            foreach (var (nextPhase, baseProbability) in transitions)
            {
                if (activePhases.Contains(nextPhase)) continue; // already active

                if (!predictions.ContainsKey(nextPhase))
                    predictions[nextPhase] = (0, []);

                var (existing, reasons) = predictions[nextPhase];
                // Combine probabilities (complementary)
                var combined = 100 - (int)((100 - existing) / 100.0 * (100 - baseProbability));
                reasons.Add($"follows from active {PhaseDefinitions[activePhase].Name}");
                predictions[nextPhase] = (combined, reasons);
            }
        }

        return predictions
            .Where(p => p.Value.probability >= 30)
            .OrderByDescending(p => p.Value.probability)
            .Take(5)
            .Select(p => new PhasePrediction
            {
                Phase = PhaseDefinitions[p.Key].Name,
                Probability = p.Value.probability,
                Rationale = string.Join("; ", p.Value.reasons.Take(3)),
                LikelyTechniques = PhaseMappings.GetValueOrDefault(p.Key, [])
                    .SelectMany(m => m.Keywords.Take(2).Select(k => $"{m.Category}/{k}"))
                    .Take(4).ToList(),
                PreventiveActions = GetPreventiveActions(p.Key),
            })
            .ToList();
    }

    private static List<string> GetPreventiveActions(int phaseIndex) => phaseIndex switch
    {
        0 => ["Minimize external exposure", "Remove unnecessary service banners", "Implement network segmentation"],
        1 => ["Enforce certificate pinning", "Maintain software inventory", "Patch management"],
        2 => ["Enforce MFA on all remote access", "Restrict inbound firewall rules", "Email filtering"],
        3 => ["Restrict PowerShell execution policy", "Application whitelisting", "Disable macros"],
        4 => ["Monitor startup locations", "Audit scheduled tasks", "Service integrity monitoring"],
        5 => ["Enforce least privilege", "Enable UAC", "Monitor privilege changes"],
        6 => ["Tamper protection for security tools", "Immutable audit logs", "File integrity monitoring"],
        7 => ["Credential Guard", "Strong password policies", "Disable credential caching"],
        8 => ["Network segmentation", "Limit discovery tools", "Monitor reconnaissance commands"],
        9 => ["Restrict admin shares", "Network access controls", "Monitor lateral protocols"],
        10 => ["DLP policies", "Monitor archive creation", "Clipboard protection"],
        11 => ["DNS filtering", "Outbound firewall rules", "Proxy inspection"],
        12 => ["Data loss prevention", "Egress filtering", "Transfer size monitoring"],
        13 => ["Offline backup verification", "Disaster recovery testing", "Immutable backups"],
        _ => ["Review security baseline"]
    };

    private static List<ResponseAction> GenerateResponsePlan(
        List<KillChainPhaseResult> phases, List<PhasePrediction> predictions)
    {
        var actions = new List<ResponseAction>();
        int priority = 1;

        // Highest-severity active phases first
        var criticalPhases = phases.Where(p => p.IsActive && p.MaxSeverity == "Critical")
            .OrderBy(p => p.PhaseIndex);
        foreach (var phase in criticalPhases)
        {
            actions.Add(new ResponseAction
            {
                Priority = priority++,
                Action = $"Immediately investigate and remediate {phase.FindingCount} critical finding(s) in {phase.Phase}",
                TargetPhase = phase.Phase,
                Urgency = "Immediate",
                Impact = "Blocks attacker progression from this phase",
            });
        }

        // Warning phases
        var warningPhases = phases.Where(p => p.IsActive && p.MaxSeverity == "Warning")
            .OrderBy(p => p.PhaseIndex);
        foreach (var phase in warningPhases)
        {
            actions.Add(new ResponseAction
            {
                Priority = priority++,
                Action = $"Address {phase.FindingCount} warning-level finding(s) in {phase.Phase}",
                TargetPhase = phase.Phase,
                Urgency = "High",
                Impact = "Reduces attack surface for this phase",
            });
        }

        // Preventive actions for predicted phases
        foreach (var pred in predictions.Take(3))
        {
            actions.Add(new ResponseAction
            {
                Priority = priority++,
                Action = $"Proactively harden against predicted {pred.Phase} phase ({pred.Probability}% likely)",
                TargetPhase = pred.Phase,
                Urgency = pred.Probability >= 70 ? "High" : "Normal",
                Impact = $"Prevents attacker from reaching {pred.Phase}",
            });
        }

        return actions.Take(10).ToList();
    }

    private static string ClassifyThreatLevel(KillChainReport report)
    {
        if (report.Progressions.Any(p => p.Severity == "Critical" && p.Confidence >= 75))
            return "Critical";
        if (report.Progressions.Any(p => p.Severity is "Critical" or "High" && p.Confidence >= 50))
            return "High";
        if (report.ActivePhaseCount >= 5)
            return "High";
        if (report.ActivePhaseCount >= 3 || report.Progressions.Count > 0)
            return "Moderate";
        if (report.ActivePhaseCount >= 1)
            return "Low";
        return "None";
    }

    private static string GenerateNarrative(KillChainReport report)
    {
        if (report.ActivePhaseCount == 0)
            return "No active kill chain phases detected. The system shows no signs of an ongoing attack.";

        var parts = new List<string>();
        parts.Add($"Analysis detected activity across {report.ActivePhaseCount} of {PhaseDefinitions.Length} kill chain phases (coverage: {report.CoverageScore}%).");

        var activeNames = report.Phases.Where(p => p.IsActive).Select(p => p.Phase).ToList();
        parts.Add($"Active phases: {string.Join(", ", activeNames)}.");

        if (report.Progressions.Count > 0)
        {
            var top = report.Progressions[0];
            parts.Add($"Detected attack pattern: \"{top.Name}\" ({top.Confidence}% confidence) — {top.Description}.");
        }

        if (report.Predictions.Count > 0)
        {
            var topPred = report.Predictions[0];
            parts.Add($"Most likely next phase: {topPred.Phase} ({topPred.Probability}% probability).");
        }

        parts.Add($"Overall threat level: {report.ThreatLevel}.");

        return string.Join(" ", parts);
    }

    // ── Internal types ──

    private record PhaseMapping(string Category, string[] Keywords);
    /// <summary>Kill chain phase definition.</summary>
    public record KillChainPhaseDef(string Name, string TacticId, int Index);
    private record AttackProgressionTemplate(string Name, string Description, int[] RequiredPhases, string Severity);
}
