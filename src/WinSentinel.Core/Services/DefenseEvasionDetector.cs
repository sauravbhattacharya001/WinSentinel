namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Defense Evasion Detector — autonomous detection of defense evasion patterns
/// across security findings. Identifies security tool tampering, log clearing,
/// masquerading, obfuscation, proxy execution, and more.
/// Groups related evasion techniques into campaigns and recommends countermeasures.
///
/// MITRE ATT&amp;CK: TA0005 (Defense Evasion)
/// Techniques: T1562.001 (Disable/Modify Security Tools), T1070.001 (Clear Event Logs),
/// T1036 (Masquerading), T1027 (Obfuscated Files), T1218 (System Binary Proxy Execution),
/// T1112 (Modify Registry), T1564.001 (Hidden Files/Directories),
/// T1140 (Deobfuscate/Decode), T1497 (Virtualization/Sandbox Evasion),
/// T1550 (Use Alternate Authentication Material)
/// </summary>
public sealed class DefenseEvasionDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<EvasionTechniqueSignature> Signatures = new()
    {
        new("Disable/Modify Security Tools", "T1562.001",
            new[] { "disable defender", "tamper protection", "disable antivirus", "stop security service", "uninstall av", "disable firewall", "disable logging", "set-mppreference", "disablerealtimemonitoring" },
            0.9, "Antivirus/EDR", "Impair Defenses"),
        new("Clear Windows Event Logs", "T1070.001",
            new[] { "wevtutil cl", "clear-eventlog", "clear event log", "event log cleared", "log deletion", "audit log cleared", "remove-eventlog" },
            0.85, "Event Logs", "Indicator Removal"),
        new("Masquerading", "T1036",
            new[] { "masquerade", "renamed executable", "legitimate name", "name mismatch", "suspicious path", "system32 impersonat", "filename spoof" },
            0.8, "Process Monitoring", "Masquerading"),
        new("Obfuscated Files/Information", "T1027",
            new[] { "obfuscat", "encoded command", "base64 encoded", "packed binary", "encrypted payload", "packer detected", "crypter" },
            0.85, "File Analysis", "Obfuscation"),
        new("System Binary Proxy Execution", "T1218",
            new[] { "mshta", "rundll32", "regsvr32", "certutil download", "msiexec", "cmstp", "installutil", "regasm" },
            0.8, "Application Control", "Proxy Execution"),
        new("Modify Registry for Defense Evasion", "T1112",
            new[] { "modify registry.*security", "tamper registry", "registry.*disable", "hklm.*security.*disabled", "registry defense evasion", "disable.*via.*registry" },
            0.75, "Registry Monitoring", "Registry Modification"),
        new("Hidden Files and Directories", "T1564.001",
            new[] { "hidden attribute", "attrib +h", "hidden directory", "concealed file", "alternate data stream", "ads:", "zone.identifier removed" },
            0.7, "File System Monitoring", "Hidden Artifacts"),
        new("Deobfuscate/Decode Files", "T1140",
            new[] { "deobfuscat", "certutil -decode", "base64 decode", "xor decrypt", "payload decode", "decode.*payload", "unpack" },
            0.75, "File Analysis", "Deobfuscation"),
        new("Virtualization/Sandbox Evasion", "T1497",
            new[] { "sandbox detect", "vm detect", "virtual machine evasion", "anti-debug", "anti-analysis", "timing evasion", "environment check" },
            0.85, "Sandbox/VM", "Environment Evasion"),
        new("Use Alternate Authentication Material", "T1550",
            new[] { "pass the hash", "pass the ticket", "golden ticket", "silver ticket", "kerberos forgery", "stolen token", "overpass" },
            0.9, "Authentication", "Credential Evasion"),
    };

    /// <summary>Indicators of automated/scripted evasion (higher urgency).</summary>
    private static readonly string[] AutomationIndicators =
        { "script", "powershell", "batch", "automated", "scheduled", "tool", "framework", "metasploit", "cobalt", "mimikatz" };

    public DefenseEvasionDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run defense evasion detection against the current security report.</summary>
    public DefenseEvasionReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new DefenseEvasionReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var evasions = new List<DefenseEvasionEvent>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectEvasions(finding, module);
            evasions.AddRange(detected);
        }

        // Scan historical findings
        foreach (var run in runs)
        {
            foreach (var fr in run.Findings)
            {
                var finding = new Finding
                {
                    Title = fr.Title,
                    Description = fr.Description,
                    Category = fr.ModuleName
                };
                var detected = DetectEvasions(finding, fr.ModuleName);
                evasions.AddRange(detected);
            }
        }

        // Deduplicate
        evasions = DeduplicateEvasions(evasions);

        result.Evasions = evasions;
        result.EvasionsDetected = evasions.Count;
        result.CriticalEvasions = evasions.Count(e => e.Severity == EvasionSeverity.Critical);
        result.HighSeverityEvasions = evasions.Count(e => e.Severity == EvasionSeverity.High);
        result.MediumSeverityEvasions = evasions.Count(e => e.Severity == EvasionSeverity.Medium);
        result.LowSeverityEvasions = evasions.Count(e => e.Severity == EvasionSeverity.Low);

        // Build campaigns
        result.Campaigns = BuildCampaigns(evasions);

        // Compute stats
        result.Stats = ComputeStats(evasions);

        // Score threat
        result.ThreatScore = ComputeThreatScore(evasions, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(evasions, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<DefenseEvasionEvent> DetectEvasions(Finding finding, string module)
    {
        var results = new List<DefenseEvasionEvent>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.1, 1.0) : sig.BaseConfidence;

            var evasion = new DefenseEvasionEvent
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                TargetDefense = sig.TargetDefense,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                EvasionCategory = sig.Category,
                Indicators = new List<string>()
            };

            if (isAutomated)
                evasion.Indicators.Add("Automated/scripted evasion detected");

            if (text.Contains("metasploit") || text.Contains("cobalt"))
                evasion.Indicators.Add("Known attack framework referenced");

            if (text.Contains("mimikatz"))
                evasion.Indicators.Add("Credential theft tool detected");

            // Severity classification
            evasion.Severity = ClassifySeverity(evasion);

            results.Add(evasion);
            break; // One technique per finding
        }

        return results;
    }

    private EvasionSeverity ClassifySeverity(DefenseEvasionEvent evasion)
    {
        // Critical: automated + disabling security tools or clearing logs
        if (evasion.IsAutomated && evasion.EvasionCategory is "Impair Defenses" or "Indicator Removal")
            return EvasionSeverity.Critical;
        if (evasion.Indicators.Any(i => i.Contains("attack framework") || i.Contains("Credential theft")))
            return EvasionSeverity.Critical;

        // High: disabling security tools, credential evasion, clearing logs
        if (evasion.EvasionCategory is "Impair Defenses" or "Credential Evasion" or "Indicator Removal")
            return EvasionSeverity.High;

        // Medium: obfuscation, proxy execution, environment evasion
        if (evasion.EvasionCategory is "Obfuscation" or "Proxy Execution" or "Environment Evasion" or "Deobfuscation")
            return EvasionSeverity.Medium;

        // Low: masquerading, hidden artifacts, registry
        return EvasionSeverity.Low;
    }

    // ── Campaign Detection ───────────────────────────────────────────

    private List<EvasionCampaign> BuildCampaigns(List<DefenseEvasionEvent> evasions)
    {
        if (evasions.Count < 2) return new();

        var campaigns = new List<EvasionCampaign>();
        var sorted = evasions.OrderBy(e => e.DetectedAt).ToList();

        // Group evasions within 24-hour windows as potential campaigns
        var windowHours = 24;
        var processed = new HashSet<int>();

        for (int i = 0; i < sorted.Count; i++)
        {
            if (processed.Contains(i)) continue;

            var cluster = new List<DefenseEvasionEvent> { sorted[i] };
            processed.Add(i);

            for (int j = i + 1; j < sorted.Count; j++)
            {
                if (processed.Contains(j)) continue;
                if ((sorted[j].DetectedAt - sorted[i].DetectedAt).TotalHours <= windowHours)
                {
                    cluster.Add(sorted[j]);
                    processed.Add(j);
                }
            }

            // Only form a campaign if 2+ different techniques are clustered
            var uniqueTechniques = cluster.Select(e => e.Technique).Distinct().Count();
            if (uniqueTechniques >= 2)
            {
                var campaign = new EvasionCampaign
                {
                    Steps = cluster,
                    TechniqueCount = uniqueTechniques,
                    Duration = cluster.Last().DetectedAt - cluster.First().DetectedAt,
                    CompoundConfidence = cluster.Aggregate(1.0, (acc, e) => acc * e.Confidence)
                };

                campaign.CampaignType = ClassifyCampaignType(cluster);
                campaign.Verdict = GenerateCampaignVerdict(campaign);
                campaigns.Add(campaign);
            }
        }

        return campaigns;
    }

    private string ClassifyCampaignType(List<DefenseEvasionEvent> cluster)
    {
        var categories = cluster.Select(e => e.EvasionCategory).Distinct().ToList();

        if (categories.Contains("Impair Defenses") && categories.Contains("Indicator Removal"))
            return "Full Stealth Operation";
        if (categories.Contains("Impair Defenses"))
            return "Security Disablement Campaign";
        if (categories.Contains("Obfuscation") && categories.Contains("Proxy Execution"))
            return "Payload Delivery Campaign";
        if (categories.Contains("Credential Evasion"))
            return "Credential Abuse Campaign";
        if (categories.Contains("Environment Evasion"))
            return "Anti-Analysis Campaign";
        return "Multi-Technique Evasion";
    }

    private string GenerateCampaignVerdict(EvasionCampaign campaign)
    {
        return campaign.CampaignType switch
        {
            "Full Stealth Operation" => $"CRITICAL: Coordinated stealth operation — {campaign.TechniqueCount} techniques used to blind defenses and erase evidence",
            "Security Disablement Campaign" => $"HIGH: Active campaign disabling security controls ({campaign.TechniqueCount} techniques)",
            "Payload Delivery Campaign" => $"HIGH: Obfuscated payload delivery using {campaign.TechniqueCount} evasion layers",
            "Credential Abuse Campaign" => $"HIGH: Credential-based evasion with {campaign.TechniqueCount} techniques",
            _ => $"Coordinated evasion campaign ({campaign.TechniqueCount} techniques over {campaign.Duration.TotalHours:F1}h)"
        };
    }

    // ── Statistics ───────────────────────────────────────────────────

    private DefenseEvasionStats ComputeStats(List<DefenseEvasionEvent> evasions)
    {
        if (evasions.Count == 0)
            return new DefenseEvasionStats();

        var techniqueGroups = evasions.GroupBy(e => e.Technique).ToList();
        var defenseGroups = evasions.GroupBy(e => e.TargetDefense).ToList();

        return new DefenseEvasionStats
        {
            TotalTechniquesUsed = techniqueGroups.Count,
            UniqueDefensesTargeted = defenseGroups.Count,
            MostTargetedDefense = defenseGroups.OrderByDescending(g => g.Count()).First().Key ?? "Unknown",
            MostCommonTechnique = techniqueGroups.OrderByDescending(g => g.Count()).First().Key,
            AverageConfidence = Math.Round(evasions.Average(e => e.Confidence), 3),
            AutomatedAttempts = evasions.Count(e => e.IsAutomated),
            ManualAttempts = evasions.Count(e => !e.IsAutomated),
            EvasionVelocity = ComputeVelocity(evasions)
        };
    }

    private double ComputeVelocity(List<DefenseEvasionEvent> evasions)
    {
        if (evasions.Count < 2) return 0;
        var sorted = evasions.OrderBy(e => e.DetectedAt).ToList();
        var span = (sorted.Last().DetectedAt - sorted.First().DetectedAt).TotalDays;
        return span > 0 ? Math.Round(evasions.Count / span, 2) : evasions.Count;
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<DefenseEvasionEvent> evasions, List<EvasionCampaign> campaigns)
    {
        if (evasions.Count == 0) return 0;

        double score = 0;

        // Base score from detections (each adds points by severity)
        foreach (var e in evasions)
        {
            score += e.Severity switch
            {
                EvasionSeverity.Critical => 15,
                EvasionSeverity.High => 10,
                EvasionSeverity.Medium => 5,
                EvasionSeverity.Low => 2,
                _ => 1
            };
        }

        // Campaign multiplier
        score += campaigns.Count * 10;

        // Automated escalation
        if (evasions.Any(e => e.IsAutomated))
            score += 10;

        // Diversity bonus (many different techniques = more sophisticated)
        var uniqueTechniques = evasions.Select(e => e.Technique).Distinct().Count();
        if (uniqueTechniques >= 4)
            score += 15;
        else if (uniqueTechniques >= 2)
            score += 5;

        return Math.Clamp((int)score, 0, 100);
    }

    private string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "High",
        >= 40 => "Moderate",
        >= 20 => "Low",
        _ => "Minimal"
    };

    // ── Recommendations ─────────────────────────────────────────────

    private List<string> GenerateRecommendations(List<DefenseEvasionEvent> evasions,
        List<EvasionCampaign> campaigns, DefenseEvasionStats stats)
    {
        var recs = new List<string>();

        if (evasions.Count == 0)
        {
            recs.Add("No defense evasion indicators detected. Continue monitoring.");
            return recs;
        }

        var categories = evasions.Select(e => e.EvasionCategory).Distinct().ToList();

        if (categories.Contains("Impair Defenses"))
            recs.Add("URGENT: Enable tamper protection on all security tools. Monitor for security service stop events.");

        if (categories.Contains("Indicator Removal"))
            recs.Add("Configure immutable log forwarding (SIEM) to prevent evidence destruction.");

        if (categories.Contains("Obfuscation") || categories.Contains("Deobfuscation"))
            recs.Add("Deploy AMSI (Anti-Malware Scan Interface) integration for in-memory script inspection.");

        if (categories.Contains("Proxy Execution"))
            recs.Add("Implement application control policies (AppLocker/WDAC) to restrict LOLBin execution.");

        if (categories.Contains("Masquerading"))
            recs.Add("Enable Sysmon with hash logging to detect renamed executables.");

        if (categories.Contains("Hidden Artifacts"))
            recs.Add("Monitor for ADS creation and hidden attribute changes via file integrity monitoring.");

        if (categories.Contains("Environment Evasion"))
            recs.Add("Harden sandbox/analysis environments to resist fingerprinting attempts.");

        if (categories.Contains("Credential Evasion"))
            recs.Add("Enforce Credential Guard and restrict NTLM authentication. Monitor for anomalous Kerberos tickets.");

        if (categories.Contains("Registry Modification"))
            recs.Add("Monitor security-relevant registry keys with real-time alerting.");

        if (campaigns.Count > 0)
            recs.Add($"ALERT: {campaigns.Count} coordinated evasion campaign(s) detected — investigate as potential active intrusion.");

        if (stats.AutomatedAttempts > stats.ManualAttempts)
            recs.Add("High automation ratio suggests toolkit usage. Scan for known offensive tools (Mimikatz, Cobalt Strike, etc.).");

        if (stats.EvasionVelocity > 2.0)
            recs.Add("Evasion velocity is high — possible active adversary. Consider incident response escalation.");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private List<DefenseEvasionEvent> DeduplicateEvasions(List<DefenseEvasionEvent> evasions)
    {
        return evasions
            .GroupBy(e => new { e.Technique, e.Evidence })
            .Select(g => g.OrderByDescending(e => e.Confidence).First())
            .ToList();
    }

    private static string? ExtractProcess(string text)
    {
        var processPatterns = new[] { "powershell", "cmd.exe", "mshta.exe", "rundll32.exe",
            "certutil.exe", "regsvr32.exe", "msiexec.exe", "schtasks.exe", "wevtutil.exe",
            "mimikatz", "rubeus" };
        return processPatterns.FirstOrDefault(p => text.Contains(p));
    }

    // ── Signature Record ─────────────────────────────────────────────

    private sealed record EvasionTechniqueSignature(
        string Name, string MitreId, string[] Keywords,
        double BaseConfidence, string TargetDefense, string Category);
}
