namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Impact Detector — autonomous detection of adversary actions that disrupt availability
/// or compromise integrity of systems and data.
///
/// MITRE ATT&amp;CK: TA0040 (Impact)
/// Techniques: T1485 (Data Destruction), T1486 (Data Encrypted for Impact),
/// T1561.002 (Disk Structure Wipe), T1489 (Service Stop),
/// T1490 (Inhibit System Recovery), T1491.001 (Internal Defacement),
/// T1491.002 (External Defacement), T1495 (Firmware Corruption),
/// T1496 (Resource Hijacking), T1498 (Network Denial of Service),
/// T1499 (Endpoint Denial of Service), T1529 (System Shutdown/Reboot)
/// </summary>
public sealed class ImpactDetector
{
    private readonly AuditHistoryService _history;

    private sealed record ImpactSignature(
        string Name, string TechniqueId, string[] Keywords, double BaseConfidence, string Category);

    private static readonly List<ImpactSignature> Signatures = new()
    {
        new("Data Destruction", "T1485",
            new[] { "data destruction", "data destroy", "file deletion mass", "mass delete",
                    "secure erase", "disk wipe", "data wipe", "file wiper", "wiper malware",
                    "data loss attack", "bulk file delete", "destroy data" },
            0.85, "Destruction"),
        new("Data Encrypted for Impact", "T1486",
            new[] { "ransomware", "encrypt files", "crypto locker", "file encryption attack",
                    "ransom note", "encrypted for ransom", "data encrypted for impact",
                    "ransomware encryption", "ransom demand", "ransom payment",
                    "file encrypt malware", "encryption attack" },
            0.90, "Ransomware"),
        new("Disk Structure Wipe", "T1561.002",
            new[] { "mbr wipe", "boot record wipe", "disk structure wipe", "partition table destroy",
                    "master boot record", "mbr overwrite", "boot sector", "disk structure destroy",
                    "partition wipe", "mbr corrupt" },
            0.90, "DiskWipe"),
        new("Service Stop", "T1489",
            new[] { "service stop attack", "kill service", "disable critical service",
                    "stop critical service", "service termination", "force stop service",
                    "net stop", "sc stop", "taskkill service", "disable service attack",
                    "service disruption" },
            0.70, "ServiceDisruption"),
        new("Inhibit System Recovery", "T1490",
            new[] { "delete shadow copies", "vssadmin delete", "bcdedit set", "disable recovery",
                    "wbadmin delete", "inhibit recovery", "shadow copy delete",
                    "backup deletion", "recovery partition delete", "disable system restore",
                    "delete backup", "vssadmin resize shadowstorage" },
            0.90, "RecoveryInhibit"),
        new("Internal Defacement", "T1491.001",
            new[] { "internal defacement", "deface intranet", "modify internal page",
                    "internal site deface", "intranet modification", "internal web deface",
                    "internal portal deface" },
            0.70, "Defacement"),
        new("External Defacement", "T1491.002",
            new[] { "external defacement", "website deface", "public defacement",
                    "web defacement", "deface website", "public site deface",
                    "homepage deface", "external web deface" },
            0.75, "Defacement"),
        new("Firmware Corruption", "T1495",
            new[] { "firmware corrupt", "bios modify", "uefi tamper", "firmware flash attack",
                    "firmware malware", "bios attack", "uefi rootkit", "firmware overwrite",
                    "bios corrupt", "uefi corrupt", "firmware wipe" },
            0.90, "Firmware"),
        new("Resource Hijacking", "T1496",
            new[] { "cryptomining", "cryptojacking", "resource hijack", "unauthorized mining",
                    "cpu abuse", "crypto miner", "mining malware", "bitcoin miner",
                    "monero mining", "coinhive", "xmrig", "resource abuse",
                    "computational hijack" },
            0.75, "ResourceHijack"),
        new("Network Denial of Service", "T1498",
            new[] { "network dos", "ddos attack", "flooding attack", "bandwidth consumption",
                    "network flood", "syn flood", "udp flood", "amplification attack",
                    "distributed denial", "ddos", "network denial of service",
                    "volumetric attack" },
            0.70, "DenialOfService"),
        new("Endpoint Denial of Service", "T1499",
            new[] { "endpoint dos", "service crash", "application dos", "resource exhaustion",
                    "application crash", "endpoint denial", "memory exhaustion",
                    "cpu exhaustion", "application flood", "service exhaustion" },
            0.70, "DenialOfService"),
        new("System Shutdown/Reboot", "T1529",
            new[] { "forced shutdown", "forced reboot", "system halt", "unexpected restart",
                    "unauthorized shutdown", "unauthorized reboot", "force restart",
                    "shutdown command attack", "system poweroff", "remote shutdown" },
            0.75, "SystemDisruption"),
    };

    /// <summary>Known destructive malware/tools.</summary>
    private static readonly string[] KnownTools =
        { "wannacry", "notpetya", "ryuk", "lockbit", "blackcat", "conti", "revil",
          "hive ransomware", "darkside", "shamoon", "destover", "stonedrill",
          "killdisk", "xmrig", "coinhive", "monero miner", "petya", "maze",
          "ragnar locker", "clop" };

    /// <summary>Indicators of destructive intent.</summary>
    private static readonly string[] DestructiveIndicators =
        { "destroy", "wipe", "erase", "corrupt", "overwrite", "delete permanently",
          "irrecoverable", "unrecoverable", "permanent loss", "bricked" };

    /// <summary>Indicators of ransom activity.</summary>
    private static readonly string[] RansomIndicators =
        { "ransom", "decrypt key", "payment", "bitcoin wallet", "tor payment",
          "encrypted files", "ransom note", "contact attacker", "decryptor" };

    /// <summary>Indicators of recovery inhibition.</summary>
    private static readonly string[] RecoveryInhibitIndicators =
        { "shadow copy", "backup delete", "recovery disable", "restore point",
          "system restore", "vssadmin", "bcdedit", "wbadmin", "safe mode" };

    /// <summary>Impact type risk ordering.</summary>
    private static readonly string[] ImpactRiskLevels =
        { "DenialOfService", "Defacement", "ServiceDisruption", "SystemDisruption",
          "ResourceHijack", "Destruction", "RecoveryInhibit", "DiskWipe",
          "Firmware", "Ransomware" };

    public ImpactDetector(AuditHistoryService history) => _history = history;

    /// <summary>Run impact detection against the current security report.</summary>
    public ImpactReport Detect(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new ImpactReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var events = new List<ImpactEvent>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectImpactEvents(finding, module);
            events.AddRange(detected);
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
                var detected = DetectImpactEvents(finding, fr.ModuleName);
                events.AddRange(detected);
            }
        }

        // Deduplicate
        events = DeduplicateEvents(events);

        result.Detections = events;
        result.ImpactDetectionsCount = events.Count;
        result.HighSeverityImpact = events.Count(e => e.Severity is ImpactSeverity.High or ImpactSeverity.Critical);
        result.MediumSeverityImpact = events.Count(e => e.Severity == ImpactSeverity.Medium);
        result.LowSeverityImpact = events.Count(e => e.Severity == ImpactSeverity.Low);

        result.Campaigns = BuildCampaigns(events);
        result.Stats = ComputeStats(events);
        result.ThreatScore = ComputeThreatScore(events, result.Campaigns);
        result.ThreatLevel = ClassifyThreatLevel(result.ThreatScore);
        result.Recommendations = GenerateRecommendations(events, result.Campaigns, result.Stats);

        return result;
    }

    // ── Detection Engine ─────────────────────────────────────────────

    private List<ImpactEvent> DetectImpactEvents(Finding finding, string module)
    {
        var results = new List<ImpactEvent>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            if (!sig.Keywords.Any(k => text.Contains(k)))
                continue;

            var isDestructive = DestructiveIndicators.Any(d => text.Contains(d));
            var confidence = isDestructive ? Math.Min(sig.BaseConfidence + 0.05, 1.0) : sig.BaseConfidence;

            var toolFound = KnownTools.FirstOrDefault(t => text.Contains(t));
            if (toolFound != null)
                confidence = Math.Min(confidence + 0.10, 1.0);

            var hasRansomIndicator = RansomIndicators.Any(r => text.Contains(r));
            if (hasRansomIndicator)
                confidence = Math.Min(confidence + 0.05, 1.0);

            var evt = new ImpactEvent
            {
                Technique = sig.Name,
                MitreTechnique = sig.TechniqueId,
                TargetAsset = ExtractAsset(text),
                ImpactType = sig.Category,
                KnownTool = toolFound,
                DetectedAt = finding.Timestamp != default ? finding.Timestamp : DateTimeOffset.UtcNow,
                Confidence = confidence,
                Evidence = finding.Title,
                IsDestructive = isDestructive || sig.Category is "Destruction" or "DiskWipe" or "Firmware",
                Indicators = new List<string>()
            };

            if (isDestructive)
                evt.Indicators.Add("Destructive intent detected — data or system integrity at risk");

            if (toolFound != null)
                evt.Indicators.Add($"Known destructive tool detected: {toolFound}");

            if (hasRansomIndicator)
                evt.Indicators.Add("Ransomware indicators detected — encryption-for-extortion activity");

            // Check for recovery inhibition
            if (RecoveryInhibitIndicators.Any(r => text.Contains(r)))
                evt.Indicators.Add("Recovery inhibition detected — backup/restore capabilities targeted");

            // Check for lateral spread
            if (text.Contains("spread") || text.Contains("propagat") || text.Contains("worm"))
                evt.Indicators.Add("Lateral spread indicators — impact may propagate across network");

            // Check for data exfiltration combo (double extortion)
            if (text.Contains("exfil") || text.Contains("steal") || text.Contains("double extortion"))
                evt.Indicators.Add("Double extortion indicators — data theft combined with impact");

            // Check for timing/urgency
            if (text.Contains("immediate") || text.Contains("rapid") || text.Contains("mass"))
                evt.Indicators.Add("Rapid/mass impact activity — urgent response required");

            evt.Severity = ClassifySeverity(evt, text);
            results.Add(evt);
            break; // One technique per finding
        }

        return results;
    }

    private ImpactSeverity ClassifySeverity(ImpactEvent evt, string text)
    {
        // Critical: ransomware + recovery inhibit, or firmware corruption, or known destructive tool + destructive
        if (evt.ImpactType == "Ransomware" && RecoveryInhibitIndicators.Any(r => text.Contains(r)))
            return ImpactSeverity.Critical;
        if (evt.ImpactType == "Firmware")
            return ImpactSeverity.Critical;
        if (evt.KnownTool != null && evt.IsDestructive)
            return ImpactSeverity.Critical;

        // High: data destruction, disk wipe, ransomware, recovery inhibit
        if (evt.ImpactType is "Destruction" or "DiskWipe" or "Ransomware" or "RecoveryInhibit")
            return ImpactSeverity.High;

        // Medium: service stop, defacement, resource hijack, system disruption
        if (evt.ImpactType is "ServiceDisruption" or "Defacement" or "ResourceHijack" or "SystemDisruption")
            return ImpactSeverity.Medium;

        // Low: DoS only
        if (evt.ImpactType == "DenialOfService")
            return ImpactSeverity.Low;

        return ImpactSeverity.Medium;
    }

    private static List<ImpactEvent> DeduplicateEvents(List<ImpactEvent> events)
    {
        var seen = new HashSet<string>();
        var deduped = new List<ImpactEvent>();
        foreach (var evt in events)
        {
            var key = $"{evt.MitreTechnique}|{evt.Evidence}";
            if (seen.Add(key))
                deduped.Add(evt);
        }
        return deduped;
    }

    private static List<ImpactCampaign> BuildCampaigns(List<ImpactEvent> events)
    {
        if (events.Count < 2) return new();

        var sorted = events.OrderBy(e => e.DetectedAt).ToList();
        var campaigns = new List<ImpactCampaign>();
        var used = new HashSet<int>();

        for (var i = 0; i < sorted.Count; i++)
        {
            if (used.Contains(i)) continue;
            var group = new List<ImpactEvent> { sorted[i] };
            used.Add(i);

            for (var j = i + 1; j < sorted.Count; j++)
            {
                if (used.Contains(j)) continue;
                var diff = sorted[j].DetectedAt - sorted[i].DetectedAt;
                if (diff.TotalHours <= 24)
                {
                    group.Add(sorted[j]);
                    used.Add(j);
                }
            }

            var distinctTechniques = group.Select(e => e.MitreTechnique).Distinct().Count();
            if (distinctTechniques < 2) continue;

            var primaryType = group.GroupBy(e => e.ImpactType ?? "unknown")
                .OrderByDescending(g => g.Count()).First();

            var assets = group.Where(e => e.TargetAsset != null).Select(e => e.TargetAsset!)
                .Distinct().ToList();

            var first = group.Min(e => e.DetectedAt);
            var last = group.Max(e => e.DetectedAt);
            var compound = 1.0 - group.Aggregate(1.0, (acc, e) => acc * (1.0 - e.Confidence));

            campaigns.Add(new ImpactCampaign
            {
                Events = group,
                PrimaryType = primaryType.Key,
                TargetSummary = assets.Count > 0 ? string.Join(", ", assets.Take(3)) : "unknown",
                TechniqueCount = distinctTechniques,
                CompoundConfidence = Math.Round(compound, 3),
                Duration = last - first,
                Verdict = distinctTechniques >= 4
                    ? "Coordinated destructive campaign — likely advanced threat actor"
                    : distinctTechniques >= 3
                        ? "Multi-technique impact operation — systematic disruption"
                        : "Related impact activity — correlated disruption techniques"
            });
        }

        return campaigns;
    }

    private static ImpactStats ComputeStats(List<ImpactEvent> events)
    {
        if (events.Count == 0)
            return new ImpactStats();

        var techniques = events.Select(e => e.MitreTechnique).Distinct().ToList();
        var tools = events.Where(e => e.KnownTool != null)
            .Select(e => e.KnownTool!).Distinct().ToList();

        var most = events.GroupBy(e => e.Technique)
            .OrderByDescending(g => g.Count()).First();

        var sortedTimes = events.Select(e => e.DetectedAt).OrderBy(t => t).ToList();
        double velocity = 0;
        if (sortedTimes.Count > 1)
        {
            var span = (sortedTimes.Last() - sortedTimes.First()).TotalDays;
            velocity = span > 0 ? Math.Round(events.Count / span, 2) : events.Count;
        }

        return new ImpactStats
        {
            TotalTechniquesUsed = techniques.Count,
            MostCommonTechnique = most.Key,
            AverageConfidence = Math.Round(events.Average(e => e.Confidence), 3),
            DestructiveEvents = events.Count(e => e.IsDestructive),
            NonDestructiveEvents = events.Count(e => !e.IsDestructive),
            AttackVelocity = velocity,
            ToolsDetected = tools.Count
        };
    }

    private static int ComputeThreatScore(List<ImpactEvent> events, List<ImpactCampaign> campaigns)
    {
        if (events.Count == 0) return 0;

        double score = 0;
        foreach (var evt in events)
        {
            score += evt.Severity switch
            {
                ImpactSeverity.Critical => 25,
                ImpactSeverity.High => 15,
                ImpactSeverity.Medium => 8,
                ImpactSeverity.Low => 3,
                _ => 0
            };
        }

        // Campaign bonus: coordinated impact is worse
        foreach (var campaign in campaigns)
        {
            score += campaign.TechniqueCount * 5;
        }

        return (int)Math.Min(score, 100);
    }

    private static string ClassifyThreatLevel(int score) => score switch
    {
        >= 80 => "Critical",
        >= 60 => "Severe",
        >= 40 => "Significant",
        >= 20 => "Moderate",
        > 0 => "Low",
        _ => "Minimal"
    };

    private static List<string> GenerateRecommendations(
        List<ImpactEvent> events, List<ImpactCampaign> campaigns, ImpactStats stats)
    {
        var recs = new List<string>();

        if (events.Count == 0)
        {
            recs.Add("No impact activity detected — maintain backup verification and disaster recovery readiness");
            return recs;
        }

        if (events.Any(e => e.MitreTechnique == "T1486"))
            recs.Add("Ransomware activity detected — isolate affected hosts, verify offline backups, engage incident response team");

        if (events.Any(e => e.MitreTechnique == "T1490"))
            recs.Add("Recovery inhibition detected — verify shadow copies and backup integrity immediately, protect backup infrastructure");

        if (events.Any(e => e.MitreTechnique == "T1485"))
            recs.Add("Data destruction detected — preserve forensic evidence, verify data integrity across all storage systems");

        if (events.Any(e => e.MitreTechnique == "T1561.002"))
            recs.Add("Disk structure wipe detected — critical threat to boot infrastructure, image affected disks for forensics");

        if (events.Any(e => e.MitreTechnique == "T1495"))
            recs.Add("Firmware corruption detected — verify BIOS/UEFI integrity, enable Secure Boot, check firmware update authenticity");

        if (events.Any(e => e.MitreTechnique == "T1496"))
            recs.Add("Resource hijacking detected — audit CPU/GPU usage, check for unauthorized mining processes, review outbound connections");

        if (events.Any(e => e.MitreTechnique == "T1489"))
            recs.Add("Service disruption detected — verify critical service status, review service control permissions, enable service recovery options");

        if (events.Any(e => e.MitreTechnique is "T1498" or "T1499"))
            recs.Add("Denial of service detected — enable rate limiting, deploy DDoS mitigation, review resource allocation thresholds");

        if (events.Any(e => e.MitreTechnique is "T1491.001" or "T1491.002"))
            recs.Add("Defacement detected — restore from known-good backups, review web application security, check for persistent access");

        if (events.Any(e => e.MitreTechnique == "T1529"))
            recs.Add("Unauthorized shutdown/reboot detected — review shutdown permissions, enable shutdown event tracking, investigate remote shutdown sources");

        if (events.Any(e => e.KnownTool != null))
        {
            var tools = events.Where(e => e.KnownTool != null)
                .Select(e => e.KnownTool!).Distinct().ToList();
            recs.Add($"Known destructive tools detected ({string.Join(", ", tools)}) — update AV/EDR signatures, scan for related IoCs across fleet");
        }

        if (stats.DestructiveEvents > 0)
            recs.Add($"{stats.DestructiveEvents} destructive event(s) detected — activate disaster recovery plan, verify RPO/RTO targets");

        if (campaigns.Count > 0)
            recs.Add($"{campaigns.Count} coordinated impact campaign(s) detected — escalate to CIRT, consider full network containment");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string? ExtractAsset(string text)
    {
        var markers = new[] { "on ", "target ", "host ", "server ", "endpoint ", "machine ", "system " };
        foreach (var m in markers)
        {
            var idx = text.IndexOf(m, StringComparison.Ordinal);
            if (idx < 0) continue;
            var start = idx + m.Length;
            var end = text.IndexOfAny(new[] { ' ', ',', '.', ';', ')', '\n' }, start);
            if (end < 0) end = Math.Min(start + 40, text.Length);
            var asset = text[start..end].Trim();
            if (asset.Length > 2) return asset;
        }
        return null;
    }
}
