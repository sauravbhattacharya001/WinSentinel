namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Discovery Detector — autonomous detection of techniques adversaries use to gain
/// knowledge about the system and internal network after initial access.
/// Identifies system enumeration, account discovery, network scanning, security
/// software detection, and other reconnaissance activities.
///
/// MITRE ATT&amp;CK: TA0007 (Discovery)
/// Techniques: T1082 (System Information Discovery), T1087 (Account Discovery),
/// T1057 (Process Discovery), T1016 (System Network Configuration Discovery),
/// T1018 (Remote System Discovery), T1083 (File and Directory Discovery),
/// T1135 (Network Share Discovery), T1069 (Permission Groups Discovery),
/// T1518 (Software Discovery), T1518.001 (Security Software Discovery),
/// T1007 (System Service Discovery), T1040 (Network Sniffing)
/// </summary>
public sealed class DiscoveryDetector
{
    private readonly AuditHistoryService _history;

    private static readonly List<DiscoverySignature> Signatures = new()
    {
        new("System Information Discovery", "T1082",
            new[] { "system information", "systeminfo", "hostname", "os version", "computer name",
                    "hardware enumeration", "system enumeration", "wmic os", "get-computerinfo", "msinfo32" },
            0.7, "System"),
        new("Account Discovery", "T1087",
            new[] { "account discovery", "user enumeration", "net user", "get-localuser", "whoami",
                    "account enumeration", "user list", "active directory user", "net group", "dsquery user" },
            0.75, "Account"),
        new("Process Discovery", "T1057",
            new[] { "process discovery", "process listing", "tasklist", "get-process", "process enumeration",
                    "running processes", "process monitor", "wmic process" },
            0.7, "Process"),
        new("System Network Configuration Discovery", "T1016",
            new[] { "network configuration", "ipconfig", "ifconfig", "get-netadapter", "network interface",
                    "arp -a", "route print", "dns configuration", "nslookup", "get-dnsclientcache" },
            0.75, "Network"),
        new("Remote System Discovery", "T1018",
            new[] { "remote system", "network scan", "ping sweep", "net view", "arp scan",
                    "nmap", "host discovery", "subnet scan", "network enumeration", "port scan" },
            0.85, "Network"),
        new("File and Directory Discovery", "T1083",
            new[] { "file discovery", "directory listing", "dir /s", "get-childitem", "file enumeration",
                    "tree command", "find files", "search files", "file search", "directory traversal" },
            0.65, "File System"),
        new("Network Share Discovery", "T1135",
            new[] { "network share", "net share", "smb enumeration", "shared folder", "get-smbshare",
                    "mount point", "unc path", "file share discovery", "share permission", "open share" },
            0.8, "Network"),
        new("Permission Groups Discovery", "T1069",
            new[] { "permission group", "group membership", "net localgroup", "get-adgroup", "admin group",
                    "privileged group", "domain admin", "group enumeration", "security group", "whoami /groups" },
            0.8, "Account"),
        new("Security Software Discovery", "T1518.001",
            new[] { "security software", "antivirus discovery", "av detection", "defender status", "security tool",
                    "edr detection", "get-mpcomputerstatus", "security product", "firewall status",
                    "wmic /namespace.*securitycenter" },
            0.85, "Security"),
        new("Software Discovery", "T1518",
            new[] { "software discovery", "installed software", "program list", "wmic product", "get-package",
                    "uninstall registry", "application inventory", "software enumeration", "installed programs", "app discovery" },
            0.7, "Software"),
        new("System Service Discovery", "T1007",
            new[] { "service discovery", "service listing", "sc query", "get-service", "service enumeration",
                    "running services", "wmic service", "net start", "service configuration", "systemctl list" },
            0.7, "Service"),
        new("Network Sniffing", "T1040",
            new[] { "network sniffing", "packet capture", "wireshark", "tcpdump", "network monitor",
                    "promiscuous mode", "packet sniff", "traffic capture", "netsh trace", "pcap" },
            0.9, "Network"),
    };

    /// <summary>Indicators of automated/scripted discovery (higher urgency).</summary>
    private static readonly string[] AutomationIndicators =
        { "automated", "script", "bot", "scanner", "mass", "sweep", "bulk", "framework", "batch" };

    /// <summary>Known reconnaissance tool names for enhanced detection.</summary>
    private static readonly string[] KnownTools =
        { "nmap", "netcat", "ncat", "bloodhound", "sharphound", "powerview",
          "adrecon", "enum4linux", "crackmapexec", "responder", "mimikatz",
          "lazagne", "seatbelt", "rubeus" };

    /// <summary>Discovery category risk ordering (low index = lower risk).</summary>
    private static readonly string[] CategoryRiskLevels =
        { "File System", "Process", "Software", "Service", "System", "Account", "Network", "Security" };

    public DiscoveryDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run discovery detection against the current security report.</summary>
    public DiscoveryReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new DiscoveryReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var activities = new List<DiscoveryActivity>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectActivities(finding, module);
            activities.AddRange(detected);
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
                var detected = DetectActivities(finding, fr.ModuleName);
                activities.AddRange(detected);
            }
        }

        // Deduplicate by technique + evidence
        activities = DeduplicateActivities(activities);

        result.Activities = activities;
        result.ActivitiesDetected = activities.Count;
        result.HighSeverityActivities = activities.Count(a => a.Severity is DiscoverySeverity.High or DiscoverySeverity.Critical);
        result.MediumSeverityActivities = activities.Count(a => a.Severity == DiscoverySeverity.Medium);
        result.LowSeverityActivities = activities.Count(a => a.Severity == DiscoverySeverity.Low);

        // Build campaigns
        result.Campaigns = BuildCampaigns(activities);

        // Compute stats
        result.Stats = ComputeStats(activities);

        // Score threat
        result.ThreatScore = ComputeThreatScore(activities, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);

        // Generate recommendations
        result.Recommendations = GenerateRecommendations(activities, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<DiscoveryActivity> DetectActivities(Finding finding, string module)
    {
        var results = new List<DiscoveryActivity>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isAutomated = AutomationIndicators.Any(a => text.Contains(a));
            var confidence = isAutomated ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            var toolFound = KnownTools.FirstOrDefault(t => text.Contains(t));
            if (toolFound != null)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var activity = new DiscoveryActivity
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                TargetAsset = ExtractAsset(text),
                DiscoveryCategory = sig.Category,
                SourceTool = toolFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                ProcessName = ExtractProcess(text),
                IsAutomated = isAutomated,
                Indicators = new List<string>()
            };

            if (isAutomated)
                activity.Indicators.Add("Automated/scripted discovery activity detected");

            if (toolFound != null)
                activity.Indicators.Add($"Known reconnaissance tool referenced: {toolFound}");

            // Check for lateral movement correlation
            if (text.Contains("pivot") || text.Contains("lateral") || text.Contains("internal"))
                activity.Indicators.Add("Discovery may be preparation for lateral movement");

            // Check for privilege escalation correlation
            if (text.Contains("privilege") || text.Contains("escalat") || text.Contains("admin"))
                activity.Indicators.Add("Discovery may be targeting privilege escalation paths");

            // Check for exfiltration planning
            if (text.Contains("exfil") || text.Contains("data collection") || text.Contains("staging"))
                activity.Indicators.Add("Discovery may be staging for data exfiltration");

            // Check for campaign indicators
            if (text.Contains("campaign") || text.Contains("mass") || text.Contains("widespread"))
                activity.Indicators.Add("Campaign-level reconnaissance detected");

            // Severity classification
            activity.Severity = ClassifySeverity(activity);

            results.Add(activity);
            break; // One technique per finding
        }

        return results;
    }

    private DiscoverySeverity ClassifySeverity(DiscoveryActivity activity)
    {
        // Critical: security software discovery with tool, network sniffing with tool, campaign
        if (activity.MitreTechnique == "T1518.001" && activity.SourceTool != null)
            return DiscoverySeverity.Critical;
        if (activity.MitreTechnique == "T1040" && activity.SourceTool != null)
            return DiscoverySeverity.Critical;
        if (activity.Indicators.Any(i => i.Contains("Campaign-level")))
            return DiscoverySeverity.Critical;

        // High: remote system discovery, network sniffing, security software discovery
        if (activity.MitreTechnique == "T1018")
            return DiscoverySeverity.High;
        if (activity.MitreTechnique == "T1040")
            return DiscoverySeverity.High;
        if (activity.MitreTechnique == "T1518.001")
            return DiscoverySeverity.High;

        // Medium: account discovery, permission groups, network shares, network config
        if (activity.DiscoveryCategory is "Account" or "Network")
            return DiscoverySeverity.Medium;

        // Low: everything else
        return DiscoverySeverity.Low;
    }

    // ── Campaign Detection ──────────────────────────────────────────

    private List<DiscoveryCampaign> BuildCampaigns(List<DiscoveryActivity> activities)
    {
        if (activities.Count < 2) return new();

        var campaigns = new List<DiscoveryCampaign>();

        // Sort by time
        var sorted = activities.OrderBy(a => a.DetectedAt).ToList();

        // Group by target asset
        var byAsset = sorted
            .Where(a => a.TargetAsset != null)
            .GroupBy(a => a.TargetAsset!)
            .Where(g => g.Count() >= 2);

        foreach (var group in byAsset)
        {
            var steps = group.OrderBy(a => a.DetectedAt).ToList();
            var campaign = new DiscoveryCampaign
            {
                Steps = steps,
                PrimaryCategory = steps
                    .GroupBy(s => s.DiscoveryCategory)
                    .OrderByDescending(g => g.Count())
                    .First().Key ?? "unknown",
                TargetSummary = group.Key,
                CategoryCount = steps.Select(s => s.DiscoveryCategory).Distinct().Count(),
                Duration = steps.Last().DetectedAt - steps.First().DetectedAt,
                CompoundConfidence = steps.Aggregate(1.0, (acc, a) => acc * a.Confidence)
            };
            campaign.Verdict = campaign.CategoryCount >= 3
                ? $"CRITICAL: Multi-category reconnaissance against {campaign.TargetSummary} using {campaign.CategoryCount} discovery categories"
                : $"Multi-activity reconnaissance against {campaign.TargetSummary} ({campaign.Steps.Count} activities)";
            campaigns.Add(campaign);
        }

        // Multi-category campaigns
        if (!campaigns.Any() && sorted.Count >= 2)
        {
            var categories = sorted.Select(a => a.DiscoveryCategory).Distinct().Count();
            if (categories >= 2)
            {
                var campaign = new DiscoveryCampaign
                {
                    Steps = sorted,
                    PrimaryCategory = sorted
                        .GroupBy(s => s.DiscoveryCategory)
                        .OrderByDescending(g => g.Count())
                        .First().Key ?? "unknown",
                    TargetSummary = "Multiple assets",
                    CategoryCount = categories,
                    Duration = sorted.Last().DetectedAt - sorted.First().DetectedAt,
                    CompoundConfidence = sorted.Aggregate(1.0, (acc, a) => acc * a.Confidence)
                };
                campaign.Verdict = $"Multi-category discovery campaign ({categories} categories, {sorted.Count} activities)";
                campaigns.Add(campaign);
            }
        }

        return campaigns;
    }

    // ── Statistics ───────────────────────────────────────────────────

    private DiscoveryStats ComputeStats(List<DiscoveryActivity> activities)
    {
        if (activities.Count == 0)
            return new DiscoveryStats();

        var techniques = activities.Select(a => a.Technique).Distinct().ToList();
        var assets = activities.Where(a => a.TargetAsset != null).Select(a => a.TargetAsset!).Distinct().ToList();
        var categories = activities.Where(a => a.DiscoveryCategory != null).Select(a => a.DiscoveryCategory!).Distinct().ToList();
        var mostCommon = activities
            .GroupBy(a => a.Technique)
            .OrderByDescending(g => g.Count())
            .First();

        var timeSpan = activities.Max(a => a.DetectedAt) - activities.Min(a => a.DetectedAt);
        var days = Math.Max(timeSpan.TotalDays, 1);

        return new DiscoveryStats
        {
            TotalTechniquesUsed = techniques.Count,
            UniqueAssetsTargeted = assets.Count,
            MostCommonTechnique = mostCommon.Key,
            AverageConfidence = Math.Round(activities.Average(a => a.Confidence), 3),
            AutomatedActivities = activities.Count(a => a.IsAutomated),
            ManualActivities = activities.Count(a => !a.IsAutomated),
            ActivityVelocity = Math.Round(activities.Count / days, 2),
            DiscoveryCategoriesUsed = categories.Count
        };
    }

    // ── Scoring ─────────────────────────────────────────────────────

    private int ComputeThreatScore(List<DiscoveryActivity> activities, List<DiscoveryCampaign> campaigns)
    {
        if (activities.Count == 0) return 0;

        double score = 0;

        // Base score from activity count and severity
        score += activities.Count(a => a.Severity == DiscoverySeverity.Critical) * 25;
        score += activities.Count(a => a.Severity == DiscoverySeverity.High) * 15;
        score += activities.Count(a => a.Severity == DiscoverySeverity.Medium) * 8;
        score += activities.Count(a => a.Severity == DiscoverySeverity.Low) * 3;

        // Campaign bonus
        score += campaigns.Count * 10;
        if (campaigns.Any(c => c.CategoryCount >= 3))
            score += 20;

        // Known tool bonus
        if (activities.Any(a => a.SourceTool != null))
            score += 15;

        // Automated activity bonus
        if (activities.Any(a => a.IsAutomated))
            score += 10;

        // Diversity bonus (more techniques = more sophisticated)
        var uniqueTechniques = activities.Select(a => a.Technique).Distinct().Count();
        if (uniqueTechniques >= 3) score += 10;
        if (uniqueTechniques >= 5) score += 10;

        // Category diversity bonus
        var uniqueCategories = activities.Select(a => a.DiscoveryCategory).Distinct().Count();
        if (uniqueCategories >= 3) score += 5;

        return (int)Math.Min(score, 100);
    }

    private string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "Elevated",
        >= 40 => "Moderate",
        >= 20 => "Low",
        _ => "Minimal"
    };

    // ── Recommendations ─────────────────────────────────────────────

    private List<string> GenerateRecommendations(List<DiscoveryActivity> activities,
        List<DiscoveryCampaign> campaigns, DiscoveryStats stats)
    {
        var recs = new List<string>();

        if (activities.Count == 0)
        {
            recs.Add("No discovery indicators detected. Continue monitoring.");
            return recs;
        }

        var techniques = activities.Select(a => a.Technique).Distinct().ToHashSet();

        if (techniques.Contains("System Information Discovery"))
            recs.Add("Monitor for unusual systeminfo/wmic os commands; enable command-line auditing via Event ID 4688 with process creation arguments; restrict WMI access to authorized accounts only.");

        if (techniques.Contains("Account Discovery"))
            recs.Add("Monitor for unusual net user/whoami commands; enable command-line auditing via Event ID 4688; restrict AD enumeration permissions; deploy honeypot accounts to detect enumeration.");

        if (techniques.Contains("Process Discovery"))
            recs.Add("Monitor for tasklist/Get-Process executed by non-admin users; restrict process visibility across sessions; enable Sysmon for detailed process tracking.");

        if (techniques.Contains("System Network Configuration Discovery"))
            recs.Add("Monitor for ipconfig/route print/nslookup usage; restrict network configuration tools to admin accounts; audit DNS client cache access patterns.");

        if (techniques.Contains("Remote System Discovery"))
            recs.Add("CRITICAL: Active network scanning detected — investigate for adversary presence; block unauthorized port scanning tools; segment networks to limit scan scope; enable IDS/IPS signatures for scan detection.");

        if (techniques.Contains("File and Directory Discovery"))
            recs.Add("Monitor for broad directory traversal patterns; implement file access auditing on sensitive directories; restrict dir/Get-ChildItem recursion depth via AppLocker.");

        if (techniques.Contains("Network Share Discovery"))
            recs.Add("Restrict SMB enumeration via SmbServerConfiguration; disable null session share access; audit share permissions regularly; monitor for net share/Get-SmbShare usage.");

        if (techniques.Contains("Permission Groups Discovery"))
            recs.Add("Monitor for net localgroup/whoami /groups commands; restrict AD group enumeration; implement tiered administration to limit visibility; deploy decoy admin groups.");

        if (techniques.Contains("Software Discovery"))
            recs.Add("Monitor for wmic product/Get-Package enumeration; restrict software inventory queries to management tools; enable application whitelisting to limit discovery value.");

        if (techniques.Contains("Security Software Discovery"))
            recs.Add("CRITICAL: Adversary probing security controls — investigate immediately; monitor for Get-MpComputerStatus/wmic securitycenter queries; ensure security tools are tamper-protected; hide security product details from non-admin users.");

        if (techniques.Contains("System Service Discovery"))
            recs.Add("Monitor for sc query/Get-Service enumeration; restrict service management tool access; enable service change auditing; watch for reconnaissance of critical services.");

        if (techniques.Contains("Network Sniffing"))
            recs.Add("CRITICAL: Active packet capture detected — investigate immediately; disable promiscuous mode on endpoints; enforce encrypted protocols (TLS/IPSec); deploy network monitoring to detect sniffing tools; restrict pcap capabilities.");

        // Campaign-level recommendations
        if (campaigns.Any(c => c.CategoryCount >= 3))
            recs.Add("CRITICAL: Multi-category reconnaissance campaign detected — activate incident response; adversary is mapping the environment systematically; assume post-compromise and begin containment.");

        if (stats.AutomatedActivities > 0)
            recs.Add("Automated reconnaissance tooling detected — investigate for active adversary; check for post-exploitation frameworks (BloodHound, SharpHound, Seatbelt); review endpoint for persistence mechanisms.");

        if (stats.ActivityVelocity > 5)
            recs.Add("High discovery activity velocity indicates active reconnaissance — increase monitoring posture; consider network isolation of affected assets.");

        if (stats.DiscoveryCategoriesUsed >= 3)
            recs.Add("Multiple discovery categories in use — adversary is building comprehensive environment knowledge; review access controls across all enumerated surfaces (accounts, network, services).");

        // General
        recs.Add("Enable Windows Event ID 4688 (process creation) with command-line logging; deploy Sysmon for enhanced telemetry; review PowerShell Script Block Logging (Event ID 4104) for encoded recon commands.");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private List<DiscoveryActivity> DeduplicateActivities(List<DiscoveryActivity> activities)
    {
        return activities
            .GroupBy(a => $"{a.Technique}|{a.Evidence}")
            .Select(g => g.First())
            .ToList();
    }

    private static string? ExtractAsset(string text)
    {
        var patterns = new[] { "server:", "host:", "target:", "system:", "endpoint:", "asset:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var asset = text[start..end].Trim();
            if (asset.Length > 0) return asset;
        }
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        var patterns = new[] { "process:", "executable:", "binary:", "program:", "tool:" };
        foreach (var p in patterns)
        {
            var idx = text.IndexOf(p, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + p.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', ';', '\n', '\r' }, start);
            if (end < 0) end = Math.Min(start + 60, text.Length);
            var proc = text[start..end].Trim();
            if (proc.Length > 0) return proc;
        }
        return null;
    }

    // ── Internal Types ──────────────────────────────────────────────

    private sealed record DiscoverySignature(
        string Name, string MitreId, string[] Keywords, double BaseConfidence, string Category);
}
