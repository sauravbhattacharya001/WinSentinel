using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Incident Response Playbook — maps security findings to structured
/// response procedures following the NIST SP 800-61 incident response
/// lifecycle: Identification → Containment → Eradication → Recovery →
/// Lessons Learned.
///
/// <para>Provides 12 built-in playbooks covering common Windows security
/// scenarios (malware, credential compromise, network intrusion, etc.).
/// Automatically matches findings to relevant playbooks by category and
/// keyword analysis, assigns priority based on finding severity and
/// blast radius, and generates actionable response plans.</para>
/// </summary>
public class IncidentResponsePlaybook
{
    // ── Data types ───────────────────────────────────────────────────

    /// <summary>NIST SP 800-61 incident response phase.</summary>
    public enum ResponsePhase
    {
        Identification,
        Containment,
        Eradication,
        Recovery,
        LessonsLearned
    }

    /// <summary>Incident priority (P1 highest → P4 lowest).</summary>
    public enum Priority
    {
        P1_Critical = 1,
        P2_High = 2,
        P3_Medium = 3,
        P4_Low = 4
    }

    /// <summary>A single step within a response phase.</summary>
    public record ResponseStep(
        ResponsePhase Phase,
        int Order,
        string Action,
        string Details,
        bool RequiresElevation,
        string? Command = null,
        TimeSpan? EstimatedDuration = null);

    /// <summary>A complete incident response playbook for a scenario.</summary>
    public record Playbook(
        string Id,
        string Name,
        string Description,
        string[] TriggerCategories,
        string[] TriggerKeywords,
        Priority DefaultPriority,
        IReadOnlyList<ResponseStep> Steps,
        string[] References)
    {
        /// <summary>Steps for a specific phase.</summary>
        public IReadOnlyList<ResponseStep> StepsForPhase(ResponsePhase phase) =>
            Steps.Where(s => s.Phase == phase).OrderBy(s => s.Order).ToList();
    }

    /// <summary>A matched playbook with priority adjusted for actual findings.</summary>
    public record PlaybookMatch(
        Playbook Playbook,
        Priority AdjustedPriority,
        IReadOnlyList<Finding> TriggeringFindings,
        double ConfidenceScore,
        string MatchReason);

    /// <summary>Full incident response plan generated from a security report.</summary>
    public record IncidentResponsePlan(
        DateTimeOffset GeneratedAt,
        int TotalFindings,
        int MatchedPlaybooks,
        Priority OverallPriority,
        IReadOnlyList<PlaybookMatch> Matches,
        IReadOnlyList<string> ImmediateActions,
        TimeSpan EstimatedResponseTime,
        string Summary);

    // ── State ────────────────────────────────────────────────────────

    private readonly Dictionary<string, Playbook> _playbooks = new(StringComparer.OrdinalIgnoreCase);

    public IncidentResponsePlaybook()
    {
        RegisterBuiltInPlaybooks();
    }

    // ── Public API ───────────────────────────────────────────────────

    /// <summary>All registered playbook IDs.</summary>
    public IReadOnlyList<string> PlaybookIds => _playbooks.Keys.ToList();

    /// <summary>All registered playbooks.</summary>
    public IReadOnlyList<Playbook> AllPlaybooks => _playbooks.Values.ToList();

    /// <summary>Get a playbook by ID.</summary>
    public Playbook? GetPlaybook(string id) =>
        _playbooks.TryGetValue(id, out var profile) ? profile : null;

    /// <summary>Register a custom playbook.</summary>
    public void RegisterPlaybook(Playbook playbook)
    {
        ArgumentNullException.ThrowIfNull(playbook);
        if (string.IsNullOrWhiteSpace(playbook.Id))
            throw new ArgumentException("Playbook ID is required.", nameof(playbook));
        _playbooks[playbook.Id] = playbook;
    }

    /// <summary>Remove a playbook by ID. Returns true if found and removed.</summary>
    public bool RemovePlaybook(string id) => _playbooks.Remove(id);

    /// <summary>
    /// Match a single finding against all playbooks.
    /// Returns matching playbooks sorted by confidence.
    /// </summary>
    public IReadOnlyList<PlaybookMatch> MatchFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var matches = new List<PlaybookMatch>();

        foreach (var pb in _playbooks.Values)
        {
            var (score, reason) = CalculateMatchScore(pb, finding);
            if (score > 0)
            {
                var priority = AdjustPriority(pb.DefaultPriority, finding.Severity);
                matches.Add(new PlaybookMatch(pb, priority, new[] { finding }, score, reason));
            }
        }

        return matches.OrderByDescending(m => m.ConfidenceScore)
                      .ThenBy(m => (int)m.AdjustedPriority)
                      .ToList();
    }

    /// <summary>
    /// Generate a full incident response plan from a security report.
    /// Matches all non-pass findings to playbooks and produces a
    /// prioritized, deduplicated action plan.
    /// </summary>
    public IncidentResponsePlan GeneratePlan(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var actionableFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity > Severity.Pass)
            .ToList();

        if (actionableFindings.Count == 0)
        {
            return new IncidentResponsePlan(
                DateTimeOffset.UtcNow, 0, 0, Priority.P4_Low,
                Array.Empty<PlaybookMatch>(),
                new[] { "No actionable findings — system is clean." },
                TimeSpan.Zero,
                "No incidents detected. All findings are passing.");
        }

        // Match findings to playbooks, grouping by playbook
        var matchesByPlaybook = new Dictionary<string, (Playbook Pb, List<Finding> Findings, double BestScore, string BestReason)>();

        foreach (var finding in actionableFindings)
        {
            foreach (var pb in _playbooks.Values)
            {
                var (score, reason) = CalculateMatchScore(pb, finding);
                if (score <= 0) continue;

                if (matchesByPlaybook.TryGetValue(pb.Id, out var existing))
                {
                    existing.Findings.Add(finding);
                    if (score > existing.BestScore)
                        matchesByPlaybook[pb.Id] = (existing.Pb, existing.Findings, score, reason);
                }
                else
                {
                    matchesByPlaybook[pb.Id] = (pb, new List<Finding> { finding }, score, reason);
                }
            }
        }

        var matches = matchesByPlaybook.Values
            .Select(m =>
            {
                var worstSeverity = m.Findings.Max(f => f.Severity);
                var priority = AdjustPriority(m.Pb.DefaultPriority, worstSeverity);
                // Boost confidence by number of triggering findings
                var boostedScore = Math.Min(1.0, m.BestScore + m.Findings.Count * 0.05);
                return new PlaybookMatch(m.Pb, priority, m.Findings.ToList(), boostedScore, m.BestReason);
            })
            .OrderBy(m => (int)m.AdjustedPriority)
            .ThenByDescending(m => m.ConfidenceScore)
            .ToList();

        var overallPriority = matches.Count > 0
            ? matches.Min(m => m.AdjustedPriority)
            : Priority.P4_Low;

        var immediateActions = GenerateImmediateActions(matches);
        var estimatedTime = EstimateResponseTime(matches);

        return new IncidentResponsePlan(
            DateTimeOffset.UtcNow,
            actionableFindings.Count,
            matches.Count,
            overallPriority,
            matches,
            immediateActions,
            estimatedTime,
            GenerateSummary(matches, actionableFindings.Count, overallPriority));
    }

    /// <summary>
    /// Generate a prioritized checklist from a plan — flattened, ordered
    /// list of all response steps across matched playbooks.
    /// </summary>
    public IReadOnlyList<(Priority Priority, string PlaybookName, ResponseStep Step)> GenerateChecklist(
        IncidentResponsePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        return plan.Matches
            .SelectMany(m => m.Playbook.Steps
                .Select(s => (m.AdjustedPriority, m.Playbook.Name, s)))
            .OrderBy(x => (int)x.AdjustedPriority)
            .ThenBy(x => (int)x.s.Phase)
            .ThenBy(x => x.s.Order)
            .ToList();
    }

    /// <summary>
    /// Generate a text report from an incident response plan.
    /// </summary>
    public string GenerateTextReport(IncidentResponsePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════╗");
        sb.AppendLine("║       INCIDENT RESPONSE PLAN                    ║");
        sb.AppendLine("╚══════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"Generated: {plan.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine($"Overall Priority: {FormatPriority(plan.OverallPriority)}");
        sb.AppendLine($"Total Findings: {plan.TotalFindings}");
        sb.AppendLine($"Matched Playbooks: {plan.MatchedPlaybooks}");
        sb.AppendLine($"Estimated Response Time: {FormatDuration(plan.EstimatedResponseTime)}");
        sb.AppendLine();

        if (plan.ImmediateActions.Count > 0)
        {
            sb.AppendLine("── IMMEDIATE ACTIONS ─────────────────────────────");
            for (int i = 0; i < plan.ImmediateActions.Count; i++)
                sb.AppendLine($"  {i + 1}. {plan.ImmediateActions[i]}");
            sb.AppendLine();
        }

        foreach (var match in plan.Matches)
        {
            sb.AppendLine($"── {match.Playbook.Name.ToUpperInvariant()} ({FormatPriority(match.AdjustedPriority)}) ──");
            sb.AppendLine($"   Confidence: {match.ConfidenceScore:P0} | Triggers: {match.TriggeringFindings.Count} finding(s)");
            sb.AppendLine($"   Match reason: {match.MatchReason}");
            sb.AppendLine();

            foreach (var phase in Enum.GetValues<ResponsePhase>())
            {
                var steps = match.Playbook.StepsForPhase(phase);
                if (steps.Count == 0) continue;

                sb.AppendLine($"   [{phase}]");
                foreach (var step in steps)
                {
                    var elevatedTag = step.RequiresElevation ? " ⚡ELEVATED" : "";
                    var duration = step.EstimatedDuration.HasValue
                        ? $" (~{FormatDuration(step.EstimatedDuration.Value)})"
                        : "";
                    sb.AppendLine($"     □ {step.Action}{elevatedTag}{duration}");
                    sb.AppendLine($"       {step.Details}");
                    if (step.Command != null)
                        sb.AppendLine($"       > {step.Command}");
                }
                sb.AppendLine();
            }
        }

        sb.AppendLine($"── SUMMARY ───────────────────────────────────────");
        sb.AppendLine(plan.Summary);

        return sb.ToString();
    }

    /// <summary>
    /// Compare two plans to see how incident response needs changed.
    /// Useful for tracking remediation progress.
    /// </summary>
    public PlanComparison ComparePlans(IncidentResponsePlan older, IncidentResponsePlan newer)
    {
        ArgumentNullException.ThrowIfNull(older);
        ArgumentNullException.ThrowIfNull(newer);

        var olderIds = older.Matches.Select(m => m.Playbook.Id).ToHashSet();
        var newerIds = newer.Matches.Select(m => m.Playbook.Id).ToHashSet();

        var resolved = older.Matches.Where(m => !newerIds.Contains(m.Playbook.Id)).ToList();
        var newIncidents = newer.Matches.Where(m => !olderIds.Contains(m.Playbook.Id)).ToList();
        var ongoing = newer.Matches.Where(m => olderIds.Contains(m.Playbook.Id)).ToList();

        var priorityImproved = ongoing.Any() && (int)newer.OverallPriority > (int)older.OverallPriority;
        var priorityDegraded = ongoing.Any() && (int)newer.OverallPriority < (int)older.OverallPriority;

        return new PlanComparison(
            older.GeneratedAt, newer.GeneratedAt,
            resolved, newIncidents, ongoing,
            older.TotalFindings - newer.TotalFindings,
            priorityImproved, priorityDegraded);
    }

    /// <summary>Result of comparing two incident response plans.</summary>
    public record PlanComparison(
        DateTimeOffset OlderPlanTime,
        DateTimeOffset NewerPlanTime,
        IReadOnlyList<PlaybookMatch> ResolvedIncidents,
        IReadOnlyList<PlaybookMatch> NewIncidents,
        IReadOnlyList<PlaybookMatch> OngoingIncidents,
        int FindingsDelta,
        bool PriorityImproved,
        bool PriorityDegraded)
    {
        /// <summary>Net improvement: resolved minus new.</summary>
        public int NetResolved => ResolvedIncidents.Count - NewIncidents.Count;
    }

    // ── Match scoring ────────────────────────────────────────────────

    private (double Score, string Reason) CalculateMatchScore(Playbook playbook, Finding finding)
    {
        double score = 0;
        var reasons = new List<string>();

        // Category match (strong signal)
        if (playbook.TriggerCategories.Any(c =>
            finding.Category.Contains(c, StringComparison.OrdinalIgnoreCase)))
        {
            score += 0.5;
            reasons.Add($"category '{finding.Category}'");
        }

        // Keyword match in title or description
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();
        var matchedKeywords = playbook.TriggerKeywords
            .Where(k => text.Contains(k.ToLowerInvariant()))
            .ToList();

        if (matchedKeywords.Count > 0)
        {
            score += Math.Min(0.5, matchedKeywords.Count * 0.15);
            reasons.Add($"keywords: {string.Join(", ", matchedKeywords.Take(3))}");
        }

        return (score, reasons.Count > 0 ? string.Join("; ", reasons) : "");
    }

    private static Priority AdjustPriority(Priority basePriority, Severity severity)
    {
        // Critical findings escalate priority by one level
        if (severity == Severity.Critical && basePriority > Priority.P1_Critical)
            return basePriority - 1;

        // Info findings de-escalate by one level
        if (severity == Severity.Info && basePriority < Priority.P4_Low)
            return basePriority + 1;

        return basePriority;
    }

    private static IReadOnlyList<string> GenerateImmediateActions(
        IReadOnlyList<PlaybookMatch> matches)
    {
        var actions = new List<string>();

        var p1Matches = matches.Where(m => m.AdjustedPriority == Priority.P1_Critical).ToList();
        if (p1Matches.Count > 0)
        {
            actions.Add("🔴 CRITICAL: Activate incident response team immediately.");
            actions.Add("Isolate affected systems from the network if active compromise is suspected.");
        }

        var p2Matches = matches.Where(m => m.AdjustedPriority == Priority.P2_High).ToList();
        if (p2Matches.Count > 0)
        {
            actions.Add("🟠 HIGH: Begin containment procedures within 1 hour.");
        }

        // Add first containment step from each P1/P2 playbook
        foreach (var match in matches.Where(m =>
            m.AdjustedPriority <= Priority.P2_High))
        {
            var containStep = match.Playbook.StepsForPhase(ResponsePhase.Containment)
                .FirstOrDefault();
            if (containStep != null)
                actions.Add($"[{match.Playbook.Name}] {containStep.Action}");
        }

        if (actions.Count == 0)
            actions.Add("No critical/high-priority incidents. Address warnings during next maintenance window.");

        return actions;
    }

    private static TimeSpan EstimateResponseTime(IReadOnlyList<PlaybookMatch> matches)
    {
        var total = TimeSpan.Zero;
        foreach (var match in matches)
        {
            foreach (var step in match.Playbook.Steps)
            {
                total += step.EstimatedDuration ?? TimeSpan.FromMinutes(15);
            }
        }
        return total;
    }

    private static string GenerateSummary(IReadOnlyList<PlaybookMatch> matches,
        int totalFindings, Priority overallPriority)
    {
        if (matches.Count == 0)
            return "No playbooks matched the current findings.";

        var byPriority = matches.GroupBy(m => m.AdjustedPriority)
            .OrderBy(g => (int)g.Key)
            .Select(g => $"{g.Count()} {g.Key}")
            .ToList();

        return $"{matches.Count} playbook(s) activated for {totalFindings} finding(s). " +
               $"Priority breakdown: {string.Join(", ", byPriority)}. " +
               $"Overall priority: {FormatPriority(overallPriority)}.";
    }

    private static string FormatPriority(Priority p) => p switch
    {
        Priority.P1_Critical => "P1 — Critical",
        Priority.P2_High     => "P2 — High",
        Priority.P3_Medium   => "P3 — Medium",
        Priority.P4_Low      => "P4 — Low",
        _ => p.ToString()
    };

    private static string FormatDuration(TimeSpan ts) =>
        ts.TotalHours >= 1 ? $"{ts.TotalHours:0.#}h"
        : ts.TotalMinutes >= 1 ? $"{ts.TotalMinutes:0}min"
        : $"{ts.TotalSeconds:0}s";

    // ── Built-in playbooks ───────────────────────────────────────────

    private void RegisterBuiltInPlaybooks()
    {
        Register_MalwareDetected();
        Register_CredentialCompromise();
        Register_NetworkIntrusion();
        Register_RansomwareThreat();
        Register_UnauthorizedAccess();
        Register_DataExfiltration();
        Register_PrivilegeEscalation();
        Register_InsecureConfiguration();
        Register_CertificateCompromise();
        Register_WirelessThreat();
        Register_SupplyChainRisk();
        Register_InsiderThreat();
    }

    private void Register_MalwareDetected()
    {
        _playbooks["malware"] = new Playbook(
            "malware", "Malware Detected",
            "Response procedure for detected malware, suspicious processes, or malicious executables.",
            new[] { "Process", "Software", "Startup" },
            new[] { "malware", "suspicious", "unsigned", "malicious", "trojan", "virus", "worm", "backdoor", "rootkit", "pup" },
            Priority.P1_Critical,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Confirm malware presence",
                    "Verify the detection with a secondary scan. Check file hash against known threat databases.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Identification, 2, "Document infected systems",
                    "Record hostname, IP, logged-in user, detection time, and malware name/hash.",
                    false),
                new(ResponsePhase.Containment, 1, "Isolate the system",
                    "Disconnect from network to prevent lateral movement. Disable Wi-Fi and unplug Ethernet.",
                    true, "netsh interface set interface \"Ethernet\" admin=disable", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Containment, 2, "Kill malicious processes",
                    "Terminate any processes associated with the malware.",
                    true, "Stop-Process -Name <process> -Force", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Containment, 3, "Disable autostart entries",
                    "Remove persistence mechanisms (startup registry keys, scheduled tasks, services).",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Eradication, 1, "Run full antivirus scan",
                    "Execute Windows Defender full scan or deploy EDR tool.",
                    true, "Start-MpScan -ScanType FullScan", TimeSpan.FromMinutes(60)),
                new(ResponsePhase.Eradication, 2, "Remove malware artifacts",
                    "Delete malicious files, clean registry entries, remove scheduled tasks.",
                    true, null, TimeSpan.FromMinutes(30)),
                new(ResponsePhase.Recovery, 1, "Restore network connectivity",
                    "Re-enable network interfaces after confirming the system is clean.",
                    true, "netsh interface set interface \"Ethernet\" admin=enable", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Recovery, 2, "Verify system integrity",
                    "Run SFC and DISM to repair any modified system files.",
                    true, "sfc /scannow", TimeSpan.FromMinutes(30)),
                new(ResponsePhase.LessonsLearned, 1, "Document infection vector",
                    "Identify how the malware entered the system (email, download, USB, exploit).",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 2, "Update defenses",
                    "Add IOCs to blocklist. Update email filters. Patch exploited vulnerability.",
                    false, null, TimeSpan.FromMinutes(20)),
            },
            new[] { "NIST SP 800-83: Guide to Malware Incident Prevention and Handling",
                    "MITRE ATT&CK: T1059 (Command and Scripting), T1547 (Boot/Logon Autostart)" });
    }

    private void Register_CredentialCompromise()
    {
        _playbooks["credential-compromise"] = new Playbook(
            "credential-compromise", "Credential Compromise",
            "Response for exposed credentials, weak passwords, credential dumping tools, or authentication failures.",
            new[] { "Account", "Credential", "Password" },
            new[] { "credential", "password", "exposed", "plaintext", "wdigest", "lsass", "mimikatz", "ntlm", "cached", "cleartext" },
            Priority.P1_Critical,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Identify exposed credentials",
                    "Determine which accounts and credential types are affected.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Identification, 2, "Check for unauthorized access",
                    "Review security event logs for logon events from unknown sources.",
                    false, "Get-WinEvent -LogName Security -FilterXPath \"*[System[EventID=4624]]\" | Select-Object -First 20", TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 1, "Force password reset",
                    "Reset passwords for all affected accounts immediately.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 2, "Disable WDigest cleartext storage",
                    "Prevent Windows from storing cleartext credentials in memory.",
                    true, "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Containment, 3, "Enable LSASS protection",
                    "Configure Credential Guard or LSASS as Protected Process Light.",
                    true, "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Eradication, 1, "Remove credential caches",
                    "Clear cached credentials and Kerberos tickets.",
                    true, "klist purge", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Eradication, 2, "Scan for credential harvesting tools",
                    "Search for known credential dumping utilities on the system.",
                    true, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Recovery, 1, "Verify credential hardening",
                    "Confirm LSASS protection and WDigest are properly configured.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.LessonsLearned, 1, "Review credential policies",
                    "Evaluate password policies, MFA adoption, and credential storage practices.",
                    false, null, TimeSpan.FromMinutes(15)),
            },
            new[] { "NIST SP 800-63B: Digital Identity Guidelines",
                    "MITRE ATT&CK: T1003 (OS Credential Dumping), T1110 (Brute Force)" });
    }

    private void Register_NetworkIntrusion()
    {
        _playbooks["network-intrusion"] = new Playbook(
            "network-intrusion", "Network Intrusion",
            "Response for suspicious network activity, open ports, unauthorized connections, or firewall gaps.",
            new[] { "Network", "Firewall", "DNS", "SMB" },
            new[] { "open port", "intrusion", "unauthorized", "lateral movement", "relay", "poisoning", "llmnr", "smb", "exposed" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Map network exposure",
                    "Identify open ports, listening services, and firewall rule gaps.",
                    false, "Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Identification, 2, "Capture network indicators",
                    "Record suspicious IPs, ports, and connection patterns.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Block suspicious connections",
                    "Add firewall rules to block identified malicious IPs or ports.",
                    true, "New-NetFirewallRule -DisplayName 'Block Threat' -Direction Inbound -RemoteAddress <IP> -Action Block", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 2, "Disable unnecessary services",
                    "Stop services listening on unnecessary ports.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Eradication, 1, "Close firewall gaps",
                    "Remove overly permissive firewall rules and restrict to minimum required ports.",
                    true, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Eradication, 2, "Disable LLMNR/NetBIOS",
                    "Prevent name resolution poisoning attacks.",
                    true, "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Recovery, 1, "Verify network hardening",
                    "Re-scan to confirm all unnecessary ports are closed and services are hardened.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Document network changes",
                    "Record all firewall and service changes for audit trail.",
                    false, null, TimeSpan.FromMinutes(10)),
            },
            new[] { "NIST SP 800-41: Firewall and Firewall Policy Guidelines",
                    "MITRE ATT&CK: T1046 (Network Service Discovery), T1557 (Adversary-in-the-Middle)" });
    }

    private void Register_RansomwareThreat()
    {
        _playbooks["ransomware"] = new Playbook(
            "ransomware", "Ransomware Threat",
            "Response for ransomware indicators: encryption activity, shadow copy deletion, suspicious file extensions.",
            new[] { "Process", "Encryption", "Software" },
            new[] { "ransomware", "encrypt", "shadow copy", "vssadmin", "bcdedit", "recovery disabled" },
            Priority.P1_Critical,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Confirm ransomware indicators",
                    "Check for encrypted files, ransom notes, suspicious file extensions.",
                    false, null, TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Containment, 1, "Immediately disconnect from network",
                    "Prevent ransomware from spreading to network shares and other systems.",
                    true, "netsh interface set interface \"Ethernet\" admin=disable", TimeSpan.FromMinutes(2)),
                new(ResponsePhase.Containment, 2, "Preserve evidence",
                    "Do NOT reboot. Take memory dump if possible for forensic analysis.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 3, "Protect backup systems",
                    "Verify backups are isolated and not affected. Disconnect backup drives.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Eradication, 1, "Identify ransomware variant",
                    "Check ransom note, file extensions, and encrypted file headers against known variants.",
                    false, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Eradication, 2, "Check for decryption tools",
                    "Search nomoreransom.org for available decryptors.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Recovery, 1, "Restore from clean backup",
                    "Restore system and data from verified clean backup.",
                    true, null, TimeSpan.FromMinutes(120)),
                new(ResponsePhase.Recovery, 2, "Rebuild if necessary",
                    "If no clean backup exists, perform a clean OS installation.",
                    true, null, TimeSpan.FromMinutes(180)),
                new(ResponsePhase.LessonsLearned, 1, "Implement ransomware defenses",
                    "Enable controlled folder access, improve backup strategy, train users.",
                    false, "Set-MpPreference -EnableControlledFolderAccess Enabled", TimeSpan.FromMinutes(30)),
            },
            new[] { "CISA Ransomware Guide: https://www.cisa.gov/stopransomware",
                    "MITRE ATT&CK: T1486 (Data Encrypted for Impact)" });
    }

    private void Register_UnauthorizedAccess()
    {
        _playbooks["unauthorized-access"] = new Playbook(
            "unauthorized-access", "Unauthorized Access",
            "Response for unauthorized user accounts, privilege misconfigurations, or remote access exposure.",
            new[] { "Account", "Remote Access" },
            new[] { "unauthorized", "remote desktop", "rdp", "admin", "guest account", "no password", "uac", "winrm" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Audit user accounts",
                    "Review all local accounts, admin group members, and guest account status.",
                    false, "Get-LocalUser | Select-Object Name, Enabled, LastLogon", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Disable unauthorized accounts",
                    "Disable guest account and any unrecognized user accounts.",
                    true, "Disable-LocalUser -Name Guest", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Containment, 2, "Restrict remote access",
                    "Disable RDP if not needed, enforce NLA, restrict RDP users.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Eradication, 1, "Enable UAC properly",
                    "Configure UAC to prompt on secure desktop for all elevation requests.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Recovery, 1, "Verify access controls",
                    "Confirm only authorized accounts have admin privileges and remote access.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Establish account review schedule",
                    "Set up periodic review of user accounts and access rights.",
                    false, null, TimeSpan.FromMinutes(10)),
            },
            new[] { "NIST SP 800-53: AC-2 (Account Management)",
                    "MITRE ATT&CK: T1078 (Valid Accounts), T1133 (External Remote Services)" });
    }

    private void Register_DataExfiltration()
    {
        _playbooks["data-exfiltration"] = new Playbook(
            "data-exfiltration", "Data Exfiltration Risk",
            "Response for data loss risks: exposed shares, clipboard monitoring, USB access, network egress.",
            new[] { "Privacy", "SMB", "Network" },
            new[] { "exfiltration", "data loss", "clipboard", "sensitive", "pii", "share", "everyone", "anonymous" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Identify exposure vectors",
                    "Audit network shares, clipboard contents, USB policy, and cloud sync services.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 1, "Restrict share permissions",
                    "Remove 'Everyone' and anonymous access from all network shares.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 2, "Enable SMB encryption",
                    "Require SMB encryption and signing to protect data in transit.",
                    true, "Set-SmbServerConfiguration -EncryptData $true -Force", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Eradication, 1, "Implement DLP controls",
                    "Configure Windows Information Protection or sensitivity labels.",
                    false, null, TimeSpan.FromMinutes(30)),
                new(ResponsePhase.Recovery, 1, "Verify data protection",
                    "Confirm shares are properly secured and monitoring is in place.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.LessonsLearned, 1, "Classify sensitive data",
                    "Create data classification policy and map sensitive data locations.",
                    false, null, TimeSpan.FromMinutes(20)),
            },
            new[] { "NIST SP 800-53: SC-8 (Transmission Confidentiality)",
                    "MITRE ATT&CK: T1041 (Exfiltration Over C2), T1567 (Exfiltration Over Web)" });
    }

    private void Register_PrivilegeEscalation()
    {
        _playbooks["privilege-escalation"] = new Playbook(
            "privilege-escalation", "Privilege Escalation Risk",
            "Response for privilege escalation vectors: unquoted paths, service misconfigurations, DLL hijacking.",
            new[] { "Service", "Startup", "Registry", "Environment" },
            new[] { "unquoted", "hijack", "dll", "writable", "elevation", "privilege", "escalat", "appinit", "ifeo" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Map escalation vectors",
                    "Identify unquoted service paths, writable program directories, and DLL search order issues.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 1, "Fix unquoted service paths",
                    "Add quotes around service binary paths that contain spaces.",
                    true, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Containment, 2, "Secure writable paths",
                    "Remove write permissions from program directories in PATH.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Eradication, 1, "Enable Safe DLL search order",
                    "Configure CWD removal from DLL search path.",
                    true, "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name SafeDllSearchMode -Value 1", TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Eradication, 2, "Clear AppInit_DLLs",
                    "Remove any entries from AppInit_DLLs registry key.",
                    true, null, TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Recovery, 1, "Verify privilege boundaries",
                    "Re-audit services and startup items to confirm fixes.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Establish service hardening baseline",
                    "Document approved service configurations and monitor for drift.",
                    false, null, TimeSpan.FromMinutes(15)),
            },
            new[] { "NIST SP 800-53: AC-6 (Least Privilege)",
                    "MITRE ATT&CK: T1574 (Hijack Execution Flow), T1543 (Create/Modify System Process)" });
    }

    private void Register_InsecureConfiguration()
    {
        _playbooks["insecure-config"] = new Playbook(
            "insecure-config", "Insecure System Configuration",
            "Response for system misconfigurations: disabled security features, weak policies, missing patches.",
            new[] { "System", "Update", "Defender", "Encryption", "GroupPolicy" },
            new[] { "disabled", "not configured", "outdated", "missing update", "weak", "insecure", "deprecated", "not enabled", "not required" },
            Priority.P3_Medium,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Catalog misconfigurations",
                    "List all non-passing findings related to system configuration.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Enable critical security features",
                    "Enable Windows Defender, firewall, and BitLocker if disabled.",
                    true, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Eradication, 1, "Apply pending updates",
                    "Install all pending Windows and driver updates.",
                    true, "Install-WindowsUpdate -AcceptAll -AutoReboot", TimeSpan.FromMinutes(60)),
                new(ResponsePhase.Eradication, 2, "Harden group policies",
                    "Apply security baselines via GPO or local security policy.",
                    true, null, TimeSpan.FromMinutes(30)),
                new(ResponsePhase.Recovery, 1, "Validate configuration",
                    "Re-run security audit to confirm all configurations are correct.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Create configuration baseline",
                    "Document approved configurations and set up drift detection.",
                    false, null, TimeSpan.FromMinutes(20)),
            },
            new[] { "CIS Benchmarks for Windows: https://www.cisecurity.org/benchmark/microsoft_windows_desktop",
                    "NIST SP 800-123: Guide to General Server Security" });
    }

    private void Register_CertificateCompromise()
    {
        _playbooks["certificate-compromise"] = new Playbook(
            "certificate-compromise", "Certificate Security Issue",
            "Response for certificate problems: expired certs, weak algorithms, untrusted CAs.",
            new[] { "Certificate" },
            new[] { "expired", "expiring", "sha-1", "sha1", "weak algorithm", "self-signed", "untrusted", "certificate", "md5" },
            Priority.P3_Medium,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Inventory affected certificates",
                    "List all expired, expiring, or weak certificates with their purposes.",
                    false, "Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Assess impact of certificate issues",
                    "Determine which services, websites, or code signing depend on affected certs.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Eradication, 1, "Replace weak/expired certificates",
                    "Request new certificates with SHA-256+ and RSA 2048+ bit keys.",
                    false, null, TimeSpan.FromMinutes(30)),
                new(ResponsePhase.Eradication, 2, "Remove untrusted root CAs",
                    "Review and remove any unknown or untrusted root certificates.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Recovery, 1, "Verify services are operational",
                    "Confirm all services are working with new certificates.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Set up certificate monitoring",
                    "Configure alerts for certificates expiring within 30/60/90 days.",
                    false, null, TimeSpan.FromMinutes(10)),
            },
            new[] { "NIST SP 800-52: TLS Implementation Guidelines",
                    "MITRE ATT&CK: T1588.004 (Obtain Capabilities: Digital Certificates)" });
    }

    private void Register_WirelessThreat()
    {
        _playbooks["wireless-threat"] = new Playbook(
            "wireless-threat", "Wireless Security Threat",
            "Response for Wi-Fi and Bluetooth security issues: weak encryption, rogue connections, exposure.",
            new[] { "WiFi", "Bluetooth" },
            new[] { "wep", "wpa-tkip", "open network", "auto-connect", "bluetooth", "discoverable", "obex", "hidden network", "probe" },
            Priority.P3_Medium,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Audit wireless profiles",
                    "Review saved Wi-Fi profiles for weak encryption or risky auto-connect settings.",
                    false, "netsh wlan show profiles", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Remove insecure profiles",
                    "Delete saved Wi-Fi profiles using WEP or open authentication.",
                    true, "netsh wlan delete profile name=\"<InsecureNetwork>\"", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 2, "Disable Bluetooth discoverability",
                    "Set Bluetooth to non-discoverable mode.",
                    true, null, TimeSpan.FromMinutes(5)),
                new(ResponsePhase.Eradication, 1, "Disable auto-connect for public networks",
                    "Configure profiles to require manual connection.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Recovery, 1, "Verify wireless hardening",
                    "Confirm only WPA2/WPA3 profiles remain and Bluetooth is secured.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.LessonsLearned, 1, "Document wireless policy",
                    "Establish approved wireless configurations and connection procedures.",
                    false, null, TimeSpan.FromMinutes(10)),
            },
            new[] { "NIST SP 800-153: Guidelines for Securing WLANs",
                    "MITRE ATT&CK: T1557.002 (ARP Cache Poisoning)" });
    }

    private void Register_SupplyChainRisk()
    {
        _playbooks["supply-chain"] = new Playbook(
            "supply-chain", "Supply Chain Risk",
            "Response for software supply chain risks: unsigned drivers, suspicious extensions, vulnerable dependencies.",
            new[] { "Driver", "Browser", "Software" },
            new[] { "unsigned", "vulnerable driver", "byovd", "extension", "permission", "outdated", "orphaned", "supply chain" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Identify untrusted components",
                    "List unsigned drivers, suspicious browser extensions, and outdated software.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 1, "Disable vulnerable drivers",
                    "Block or remove unsigned and known-vulnerable (BYOVD) drivers.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Containment, 2, "Remove suspicious extensions",
                    "Uninstall browser extensions with excessive permissions or low reputation.",
                    false, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Eradication, 1, "Update vulnerable software",
                    "Patch or replace outdated and orphaned software installations.",
                    true, null, TimeSpan.FromMinutes(30)),
                new(ResponsePhase.Eradication, 2, "Enable driver signing enforcement",
                    "Ensure Secure Boot is enabled and test signing mode is disabled.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Recovery, 1, "Verify component integrity",
                    "Re-scan to confirm all drivers are signed and software is current.",
                    false, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.LessonsLearned, 1, "Establish software approval process",
                    "Create an approved software list and driver signing policy.",
                    false, null, TimeSpan.FromMinutes(15)),
            },
            new[] { "NIST SP 800-161: Supply Chain Risk Management Practices",
                    "MITRE ATT&CK: T1195 (Supply Chain Compromise)" });
    }

    private void Register_InsiderThreat()
    {
        _playbooks["insider-threat"] = new Playbook(
            "insider-threat", "Insider Threat Indicators",
            "Response for insider threat indicators: suspicious scheduled tasks, persistence mechanisms, event log gaps.",
            new[] { "ScheduledTask", "EventLog", "Service", "Registry" },
            new[] { "encoded command", "persistence", "hidden task", "log cleared", "audit gap", "tamper", "userinit", "winlogon", "debugger" },
            Priority.P2_High,
            new ResponseStep[]
            {
                new(ResponsePhase.Identification, 1, "Review persistence mechanisms",
                    "Audit scheduled tasks, services, registry run keys, and Winlogon entries for suspicious items.",
                    false, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Identification, 2, "Check event log integrity",
                    "Look for gaps in security logs or evidence of log clearing.",
                    false, "Get-WinEvent -LogName Security -MaxEvents 1 | Select-Object RecordId", TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Containment, 1, "Remove suspicious persistence",
                    "Disable or delete unauthorized scheduled tasks, services, and registry entries.",
                    true, null, TimeSpan.FromMinutes(20)),
                new(ResponsePhase.Containment, 2, "Enable comprehensive auditing",
                    "Ensure security event logging is configured and protected.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.Eradication, 1, "Scan for encoded/obfuscated commands",
                    "Search for base64-encoded or obfuscated PowerShell commands in tasks and scripts.",
                    true, null, TimeSpan.FromMinutes(15)),
                new(ResponsePhase.Recovery, 1, "Restore log integrity",
                    "Verify audit policies are enabled and logs are being collected.",
                    true, null, TimeSpan.FromMinutes(10)),
                new(ResponsePhase.LessonsLearned, 1, "Implement monitoring",
                    "Set up alerts for new scheduled tasks, services, and registry modifications.",
                    false, null, TimeSpan.FromMinutes(15)),
            },
            new[] { "NIST SP 800-53: AU-2 (Audit Events), SI-4 (Information System Monitoring)",
                    "MITRE ATT&CK: T1053 (Scheduled Task/Job), T1112 (Modify Registry)" });
    }
}
