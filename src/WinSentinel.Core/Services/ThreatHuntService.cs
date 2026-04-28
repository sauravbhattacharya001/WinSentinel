namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Threat Hunt Engine — proactively generates and executes hunt
/// hypotheses based on current findings, history patterns, and known threat
/// indicators. Instead of waiting for alerts, it actively seeks threats
/// that existing audit modules might miss or under-prioritize.
/// </summary>
public sealed class ThreatHuntService
{
    private readonly AuditHistoryService _history;

    public ThreatHuntService(AuditHistoryService history) => _history = history;

    /// <summary>Execute a full threat hunt cycle against current findings and history.</summary>
    public HuntReport Hunt(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results.SelectMany(m =>
            m.Findings.Select(f => new HuntFinding(f, m.ModuleName))).ToList();

        var result = new HuntReport
        {
            TotalFindings = findings.Count(),
            HistoryRunsAnalyzed = runs.Count,
            HuntTimestamp = DateTimeOffset.UtcNow
        };

        // Generate and execute hypotheses
        var hypotheses = new List<HuntHypothesis>();
        hypotheses.AddRange(HuntLateralMovement(findings));
        hypotheses.AddRange(HuntPersistenceMechanisms(findings));
        hypotheses.AddRange(HuntPrivilegeEscalation(findings));
        hypotheses.AddRange(HuntDataExfiltration(findings));
        hypotheses.AddRange(HuntDefenseEvasion(findings));
        hypotheses.AddRange(HuntShadowAdmins(findings));
        hypotheses.AddRange(HuntStaleCredentials(findings));
        hypotheses.AddRange(HuntPhantomServices(findings, runs));

        result.Hypotheses = hypotheses.OrderByDescending(h => h.ThreatScore).ToList();
        result.ConfirmedThreats = hypotheses.Count(h => h.Status == HuntStatus.Confirmed);
        result.SuspiciousFindings = hypotheses.Count(h => h.Status == HuntStatus.Suspicious);
        result.ClearedHypotheses = hypotheses.Count(h => h.Status == HuntStatus.Cleared);
        result.TotalHypotheses = hypotheses.Count;

        // Calculate overall threat hunt score (0-100, lower = more threats found)
        if (hypotheses.Count > 0)
        {
            var maxPossible = hypotheses.Count * 100.0;
            var actualScore = hypotheses.Sum(h => h.ThreatScore);
            result.HuntScore = Math.Clamp(100 - (int)(actualScore / maxPossible * 100), 0, 100);
        }
        else
        {
            result.HuntScore = 100;
        }

        // Generate recommended actions
        result.RecommendedActions = GenerateActions(hypotheses);

        return result;
    }

    // ═══════════════════════════════════════════
    //  Hunt Hypotheses
    // ═══════════════════════════════════════════

    /// <summary>
    /// Hypothesis: Lateral movement — look for signs of network traversal:
    /// open SMB shares + remote access + weak network config.
    /// </summary>
    private static List<HuntHypothesis> HuntLateralMovement(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var smbFindings = findings.Where(f =>
            f.Category.Contains("SMB", StringComparison.OrdinalIgnoreCase) ||
            f.Category.Contains("Share", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("share", StringComparison.OrdinalIgnoreCase)).ToList();

        var remoteFindings = findings.Where(f =>
            f.Title.Contains("Remote", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("RDP", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("SSH", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("WinRM", StringComparison.OrdinalIgnoreCase)).ToList();

        var networkFindings = findings.Where(f =>
            f.Module.Contains("Network", StringComparison.OrdinalIgnoreCase) ||
            f.Module.Contains("Firewall", StringComparison.OrdinalIgnoreCase)).ToList();

        if (smbFindings.Count > 0 || remoteFindings.Count > 0)
        {
            var evidence = smbFindings.Concat(remoteFindings).Concat(networkFindings).ToList();
            var score = CalculateHypothesisScore(evidence);
            var hasBoth = smbFindings.Count > 0 && remoteFindings.Count > 0;

            results.Add(new HuntHypothesis
            {
                Name = "Lateral Movement Potential",
                MitreId = "TA0008",
                Description = "Investigating potential lateral movement vectors: " +
                    $"{smbFindings.Count} SMB/share findings, {remoteFindings.Count} remote access findings, " +
                    $"{networkFindings.Count} network misconfigurations.",
                Status = hasBoth && score >= 40 ? HuntStatus.Confirmed
                    : evidence.Count >= 2 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score,
                Evidence = evidence.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = hasBoth
                    ? "CRITICAL: Open shares combined with remote access creates lateral movement path. Disable unnecessary shares and restrict remote access."
                    : "Review and restrict remote access services and file shares."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Persistence mechanisms — look for suspicious startup items,
    /// scheduled tasks, and services that could maintain attacker access.
    /// </summary>
    private static List<HuntHypothesis> HuntPersistenceMechanisms(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var startupFindings = findings.Where(f =>
            f.Module.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("startup", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("auto-start", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("autorun", StringComparison.OrdinalIgnoreCase)).ToList();

        var taskFindings = findings.Where(f =>
            f.Module.Contains("ScheduledTask", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("scheduled task", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("task scheduler", StringComparison.OrdinalIgnoreCase)).ToList();

        var serviceFindings = findings.Where(f =>
            f.Module.Contains("Service", StringComparison.OrdinalIgnoreCase) &&
            (f.Severity == Severity.Warning || f.Severity == Severity.Critical)).ToList();

        var registryFindings = findings.Where(f =>
            f.Module.Contains("Registry", StringComparison.OrdinalIgnoreCase) &&
            (f.Title.Contains("Run", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("startup", StringComparison.OrdinalIgnoreCase))).ToList();

        var allEvidence = startupFindings.Concat(taskFindings).Concat(serviceFindings).Concat(registryFindings).ToList();

        if (allEvidence.Count > 0)
        {
            var score = CalculateHypothesisScore(allEvidence);
            var categories = new[] { startupFindings.Count > 0, taskFindings.Count > 0, serviceFindings.Count > 0, registryFindings.Count > 0 }
                .Count(x => x);

            results.Add(new HuntHypothesis
            {
                Name = "Persistence Mechanism Abuse",
                MitreId = "TA0003",
                Description = $"Investigating {allEvidence.Count} potential persistence mechanisms across " +
                    $"{categories} categories (startup: {startupFindings.Count}, tasks: {taskFindings.Count}, " +
                    $"services: {serviceFindings.Count}, registry: {registryFindings.Count}).",
                Status = categories >= 3 ? HuntStatus.Confirmed
                    : categories >= 2 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score + (categories * 10),
                Evidence = allEvidence.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = categories >= 2
                    ? "Multiple persistence vectors detected. Audit all startup items, scheduled tasks, and services for unauthorized entries."
                    : "Review flagged persistence mechanisms for legitimacy."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Privilege escalation — look for weak permissions, unpatched
    /// vulnerabilities, and misconfigured accounts that enable escalation.
    /// </summary>
    private static List<HuntHypothesis> HuntPrivilegeEscalation(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var accountFindings = findings.Where(f =>
            f.Module.Contains("Account", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("privilege", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("elevated", StringComparison.OrdinalIgnoreCase)).ToList();

        var updateFindings = findings.Where(f =>
            f.Module.Contains("Update", StringComparison.OrdinalIgnoreCase) &&
            f.Severity >= Severity.Warning).ToList();

        var policyFindings = findings.Where(f =>
            f.Module.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("UAC", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("policy", StringComparison.OrdinalIgnoreCase)).ToList();

        var allEvidence = accountFindings.Concat(updateFindings).Concat(policyFindings).ToList();

        if (allEvidence.Count > 0)
        {
            var score = CalculateHypothesisScore(allEvidence);
            var hasUnpatched = updateFindings.Count > 0;
            var hasWeakAccounts = accountFindings.Any(f => f.Severity >= Severity.Warning);

            results.Add(new HuntHypothesis
            {
                Name = "Privilege Escalation Risk",
                MitreId = "TA0004",
                Description = $"Analyzing privilege escalation potential: {accountFindings.Count} account issues, " +
                    $"{updateFindings.Count} missing patches, {policyFindings.Count} policy weaknesses.",
                Status = hasUnpatched && hasWeakAccounts ? HuntStatus.Confirmed
                    : allEvidence.Count >= 3 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score,
                Evidence = allEvidence.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = hasUnpatched && hasWeakAccounts
                    ? "HIGH RISK: Unpatched system with weak account controls. Apply updates immediately and review admin accounts."
                    : "Strengthen account policies and keep system patched."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Data exfiltration — look for open ports, weak encryption,
    /// clipboard exposure, and network misconfigurations that enable data theft.
    /// </summary>
    private static List<HuntHypothesis> HuntDataExfiltration(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var encryptionFindings = findings.Where(f =>
            f.Module.Contains("Encryption", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("BitLocker", StringComparison.OrdinalIgnoreCase)).ToList();

        var clipboardFindings = findings.Where(f =>
            f.Title.Contains("clipboard", StringComparison.OrdinalIgnoreCase)).ToList();

        var networkExposure = findings.Where(f =>
            f.Title.Contains("port", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("listen", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("exposed", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("open", StringComparison.OrdinalIgnoreCase)).ToList();

        var privacyFindings = findings.Where(f =>
            f.Module.Contains("Privacy", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("telemetry", StringComparison.OrdinalIgnoreCase)).ToList();

        var allEvidence = encryptionFindings.Concat(clipboardFindings).Concat(networkExposure).Concat(privacyFindings).ToList();

        if (allEvidence.Count > 0)
        {
            var score = CalculateHypothesisScore(allEvidence);
            var categories = new[] { encryptionFindings.Count > 0, clipboardFindings.Count > 0, networkExposure.Count > 0, privacyFindings.Count > 0 }
                .Count(x => x);

            results.Add(new HuntHypothesis
            {
                Name = "Data Exfiltration Vectors",
                MitreId = "TA0010",
                Description = $"Hunting data exfiltration paths: {encryptionFindings.Count} encryption gaps, " +
                    $"{networkExposure.Count} network exposures, {clipboardFindings.Count} clipboard risks, " +
                    $"{privacyFindings.Count} privacy concerns.",
                Status = categories >= 3 ? HuntStatus.Confirmed
                    : categories >= 2 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score,
                Evidence = allEvidence.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = categories >= 3
                    ? "Multiple exfiltration vectors open. Enable encryption, restrict clipboard access, and review open ports."
                    : "Address identified data exposure risks."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Defense evasion — look for disabled security tools, tampered
    /// logs, and configuration that helps attackers hide.
    /// </summary>
    private static List<HuntHypothesis> HuntDefenseEvasion(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var defenderFindings = findings.Where(f =>
            f.Module.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
            f.Severity >= Severity.Warning).ToList();

        var logFindings = findings.Where(f =>
            f.Module.Contains("EventLog", StringComparison.OrdinalIgnoreCase) &&
            (f.Title.Contains("disabled", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("cleared", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("size", StringComparison.OrdinalIgnoreCase))).ToList();

        var powershellFindings = findings.Where(f =>
            f.Module.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) &&
            (f.Title.Contains("logging", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("execution policy", StringComparison.OrdinalIgnoreCase))).ToList();

        var allEvidence = defenderFindings.Concat(logFindings).Concat(powershellFindings).ToList();

        if (allEvidence.Count > 0)
        {
            var score = CalculateHypothesisScore(allEvidence);
            var defenderDown = defenderFindings.Count > 0;
            var logsWeakened = logFindings.Count > 0;

            results.Add(new HuntHypothesis
            {
                Name = "Defense Evasion Indicators",
                MitreId = "TA0005",
                Description = $"Checking for defense evasion: {defenderFindings.Count} Defender issues, " +
                    $"{logFindings.Count} logging gaps, {powershellFindings.Count} PowerShell concerns.",
                Status = defenderDown && logsWeakened ? HuntStatus.Confirmed
                    : allEvidence.Count >= 2 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score + (defenderDown ? 20 : 0),
                Evidence = allEvidence.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = defenderDown && logsWeakened
                    ? "CRITICAL: Security tools disabled AND logging weakened — classic defense evasion pattern. Re-enable Defender and audit logging immediately."
                    : "Ensure all security monitoring tools are active and logging is comprehensive."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Shadow admins — look for accounts with admin-level access
    /// that shouldn't have it (non-standard admin accounts, too many admins).
    /// </summary>
    private static List<HuntHypothesis> HuntShadowAdmins(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var adminFindings = findings.Where(f =>
            (f.Title.Contains("admin", StringComparison.OrdinalIgnoreCase) &&
             (f.Title.Contains("group", StringComparison.OrdinalIgnoreCase) ||
              f.Title.Contains("member", StringComparison.OrdinalIgnoreCase) ||
              f.Title.Contains("account", StringComparison.OrdinalIgnoreCase))) ||
            f.Title.Contains("built-in admin", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("guest", StringComparison.OrdinalIgnoreCase)).ToList();

        if (adminFindings.Count > 0)
        {
            var score = CalculateHypothesisScore(adminFindings);

            results.Add(new HuntHypothesis
            {
                Name = "Shadow Admin Accounts",
                MitreId = "T1078",
                Description = $"Hunting for unauthorized admin accounts: {adminFindings.Count} account-related findings.",
                Status = adminFindings.Count >= 3 ? HuntStatus.Confirmed
                    : adminFindings.Count >= 1 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score,
                Evidence = adminFindings.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = "Audit all accounts with administrative privileges. Remove unnecessary admin memberships."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Stale credentials — look for password policy weaknesses,
    /// old accounts, and credential exposure that attackers exploit.
    /// </summary>
    private static List<HuntHypothesis> HuntStaleCredentials(List<HuntFinding> findings)
    {
        var results = new List<HuntHypothesis>();

        var credFindings = findings.Where(f =>
            f.Module.Contains("Credential", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("password", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("token", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("secret", StringComparison.OrdinalIgnoreCase)).ToList();

        if (credFindings.Count > 0)
        {
            var score = CalculateHypothesisScore(credFindings);
            var hasCritical = credFindings.Any(f => f.Severity == Severity.Critical);

            results.Add(new HuntHypothesis
            {
                Name = "Stale / Exposed Credentials",
                MitreId = "T1552",
                Description = $"Scanning for credential risks: {credFindings.Count} credential-related findings.",
                Status = hasCritical ? HuntStatus.Confirmed
                    : credFindings.Count >= 2 ? HuntStatus.Suspicious
                    : HuntStatus.Cleared,
                ThreatScore = score,
                Evidence = credFindings.Select(f => f.Title).Distinct().Take(8).ToList(),
                Recommendation = hasCritical
                    ? "CRITICAL: Exposed credentials detected. Rotate all compromised credentials immediately."
                    : "Review and strengthen credential policies."
            });
        }

        return results;
    }

    /// <summary>
    /// Hypothesis: Phantom services — findings that appear and disappear across
    /// audit runs, suggesting intermittent malicious activity that tries to avoid
    /// detection by running only periodically.
    /// </summary>
    private static List<HuntHypothesis> HuntPhantomServices(List<HuntFinding> findings, List<AuditRunRecord> runs)
    {
        var results = new List<HuntHypothesis>();

        if (runs.Count < 3) return results;

        // Look for findings that appear intermittently (in some runs but not others)
        var findingPresence = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var findingSeverity = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase);

        foreach (var run in runs)
        {
            var runFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var module in run.ModuleScores ?? [])
            {
                // Track module-level presence
                if (module.Score < 100) // Module had findings
                    runFindings.Add(module.ModuleName);
            }
            foreach (var title in runFindings)
            {
                findingPresence.TryGetValue(title, out var count);
                findingPresence[title] = count + 1;
            }
        }

        // Intermittent = present in 20-80% of runs (not always, not rarely)
        var intermittent = findingPresence
            .Where(kv => {
                var pct = (double)kv.Value / runs.Count;
                return pct >= 0.2 && pct <= 0.8;
            })
            .OrderByDescending(kv => kv.Value)
            .Take(5)
            .ToList();

        if (intermittent.Count > 0)
        {
            results.Add(new HuntHypothesis
            {
                Name = "Phantom / Intermittent Activity",
                MitreId = "T1036",
                Description = $"Detected {intermittent.Count} modules with intermittent finding patterns " +
                    $"across {runs.Count} audit runs. This may indicate periodic malicious activity " +
                    $"designed to evade continuous monitoring.",
                Status = intermittent.Count >= 3 ? HuntStatus.Suspicious : HuntStatus.Cleared,
                ThreatScore = intermittent.Count * 12,
                Evidence = intermittent.Select(kv =>
                    $"{kv.Key} (present in {kv.Value}/{runs.Count} runs = {kv.Value * 100 / runs.Count}%)").ToList(),
                Recommendation = "Investigate intermittent modules for scheduled malicious tasks or rootkits that periodically activate."
            });
        }

        return results;
    }

    // ═══════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════

    private static int CalculateHypothesisScore(List<HuntFinding> evidence)
    {
        if (evidence.Count == 0) return 0;

        var baseScore = evidence.Sum(f => f.Severity switch
        {
            Severity.Critical => 30,
            Severity.Warning => 15,
            Severity.Info => 5,
            _ => 1
        });

        // Bonus for evidence from multiple modules (cross-module correlation)
        var moduleCount = evidence.Select(f => f.Module).Distinct().Count();
        var crossModuleBonus = (moduleCount - 1) * 10;

        return Math.Clamp(baseScore + crossModuleBonus, 0, 100);
    }

    private static List<HuntAction> GenerateActions(List<HuntHypothesis> hypotheses)
    {
        var actions = new List<HuntAction>();
        var priority = 1;

        foreach (var h in hypotheses.Where(h => h.Status == HuntStatus.Confirmed).OrderByDescending(h => h.ThreatScore))
        {
            actions.Add(new HuntAction
            {
                Priority = priority++,
                Urgency = h.ThreatScore >= 60 ? "Immediate" : "High",
                HypothesisName = h.Name,
                Action = h.Recommendation,
                MitreId = h.MitreId
            });
        }

        foreach (var h in hypotheses.Where(h => h.Status == HuntStatus.Suspicious).OrderByDescending(h => h.ThreatScore))
        {
            actions.Add(new HuntAction
            {
                Priority = priority++,
                Urgency = "Medium",
                HypothesisName = h.Name,
                Action = h.Recommendation,
                MitreId = h.MitreId
            });
        }

        return actions;
    }
}

// ═══════════════════════════════════════════════
//  Models
// ═══════════════════════════════════════════════

/// <summary>Internal wrapper for finding + source module.</summary>
public sealed class HuntFinding
{
    public string Title { get; }
    public string Description { get; }
    public Severity Severity { get; }
    public string Category { get; }
    public string Module { get; }

    public HuntFinding(Finding f, string module)
    {
        Title = f.Title;
        Description = f.Description;
        Severity = f.Severity;
        Category = f.Category;
        Module = module;
    }
}

public sealed class HuntReport
{
    public DateTimeOffset HuntTimestamp { get; set; }
    public int TotalFindings { get; set; }
    public int HistoryRunsAnalyzed { get; set; }
    public int TotalHypotheses { get; set; }
    public int ConfirmedThreats { get; set; }
    public int SuspiciousFindings { get; set; }
    public int ClearedHypotheses { get; set; }
    public int HuntScore { get; set; } = 100;
    public List<HuntHypothesis> Hypotheses { get; set; } = [];
    public List<HuntAction> RecommendedActions { get; set; } = [];
}

public sealed class HuntHypothesis
{
    public string Name { get; set; } = "";
    public string MitreId { get; set; } = "";
    public string Description { get; set; } = "";
    public HuntStatus Status { get; set; }
    public int ThreatScore { get; set; }
    public List<string> Evidence { get; set; } = [];
    public string Recommendation { get; set; } = "";
}

public sealed class HuntAction
{
    public int Priority { get; set; }
    public string Urgency { get; set; } = "";
    public string HypothesisName { get; set; } = "";
    public string Action { get; set; } = "";
    public string MitreId { get; set; } = "";
}

public enum HuntStatus
{
    Cleared,
    Suspicious,
    Confirmed
}
