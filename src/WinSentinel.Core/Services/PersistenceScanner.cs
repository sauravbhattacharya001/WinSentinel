namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Persistence Mechanism Scanner — autonomous detection of persistence techniques
/// across security findings. Identifies registry run keys, scheduled tasks,
/// services, WMI subscriptions, startup folder abuse, DLL hijacking,
/// boot/logon scripts, IFEO debugger keys, AppInit DLLs, and browser extensions.
///
/// MITRE ATT&amp;CK: TA0003 (Persistence)
/// Techniques: T1547.001 (Registry Run Keys / Startup Folder),
/// T1053.005 (Scheduled Task/Job), T1543.003 (Windows Service),
/// T1546.003 (WMI Event Subscription), T1574.001 (DLL Search Order Hijacking),
/// T1037 (Boot or Logon Initialization Scripts), T1546.012 (Image File Execution Options),
/// T1546.010 (AppInit DLLs), T1176 (Browser Extensions)
/// </summary>
public sealed class PersistenceMechScanner
{
    private readonly AuditHistoryService _history;

    private static readonly List<PersistTechniqueSignature> Signatures = new()
    {
        new("Registry Run/RunOnce Keys", "T1547.001",
            new[] { "currentversion\\run", "runonce", "runservices", "hklm\\software\\microsoft\\windows\\currentversion\\run", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "registry run key", "run key" },
            0.85, "Registry"),
        new("Scheduled Tasks", "T1053.005",
            new[] { "schtasks", "scheduled task", "task scheduler", "taskschd", "at.exe", "register-scheduledjob", "/create /tn" },
            0.80, "Task Scheduler"),
        new("Windows Services", "T1543.003",
            new[] { "sc create", "new-service", "service creation", "localsystem", "createservice", "service install", "binpath" },
            0.85, "Services"),
        new("WMI Event Subscriptions", "T1546.003",
            new[] { "wmi event", "wmi subscription", "eventconsumer", "commandlineeventconsumer", "activescripteventconsumer", "__eventfilter", "wmi persistence", "managementobject" },
            0.90, "WMI"),
        new("Startup Folder", "T1547.001",
            new[] { "startup folder", "shell:startup", "shell:common startup", "programs\\startup", "start menu\\programs\\startup", ".lnk startup" },
            0.75, "Filesystem"),
        new("DLL Search Order Hijacking", "T1574.001",
            new[] { "dll hijack", "phantom dll", "dll search order", "dll proxying", "dll side-load", "known dlls", "dll planting" },
            0.85, "DLL"),
        new("Boot/Logon Scripts", "T1037",
            new[] { "userinitmprlogon", "logon script", "gpo script", "boot script", "winlogon", "logon init", "group policy script", "netlogon" },
            0.80, "Scripts"),
        new("Image File Execution Options", "T1546.012",
            new[] { "image file execution", "ifeo", "debugger key", "silentprocessexit", "globalflag", "image hijack" },
            0.90, "IFEO"),
        new("AppInit DLLs", "T1546.010",
            new[] { "appinit_dlls", "appinit", "loadappinit_dlls", "appinit registry" },
            0.90, "AppInit"),
        new("Browser Extensions", "T1176",
            new[] { "browser extension", "chrome extension", "firefox addon", "edge extension", "extension install", "extension policy", "extensioninstallforce" },
            0.70, "Browser"),
    };

    /// <summary>Indicators that a persistence mechanism is dormant.</summary>
    private static readonly string[] DormancyIndicators = { "disabled", "inactive", "orphan", "stale", "old", "legacy", "removed", "expired", "obsolete" };

    /// <summary>Indicators that a persistence mechanism is actively executing.</summary>
    private static readonly string[] ActivityIndicators = { "active", "running", "triggered", "executed", "loaded", "recent", "enabled", "started", "firing" };

    public PersistenceMechScanner(AuditHistoryService history) => _history = history;

    /// <summary>Scan security findings for persistence mechanisms.</summary>
    public PersistMechReport Scan(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results
            .SelectMany(m => m.Findings.Select(f => (Finding: f, Module: m.ModuleName)))
            .ToList();

        var result = new PersistMechReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        var entries = new List<PersistMechEntry>();

        // Detect from current findings
        foreach (var (finding, module) in findings)
        {
            var detected = DetectPersistence(finding, module);
            entries.AddRange(detected);
        }

        // Scan historical findings
        foreach (var run in runs)
        {
            foreach (var fr in run.Findings)
            {
                var detected = DetectFromRecord(fr);
                entries.AddRange(detected);
            }
        }

        // Deduplicate by technique + location + evidence
        entries = entries
            .GroupBy(e => $"{e.MitreTechnique}|{e.Location}|{e.Evidence}")
            .Select(g => g.OrderByDescending(e => e.Confidence).First())
            .ToList();

        result.Entries = entries;
        result.MechanismsDetected = entries.Count;
        result.ActiveMechanisms = entries.Count(e => e.IsActive);
        result.DormantMechanisms = entries.Count(e => e.IsDormant);
        result.CriticalMechanisms = entries.Count(e => e.Severity == PersistMechSeverity.Critical);
        result.HighMechanisms = entries.Count(e => e.Severity == PersistMechSeverity.High);
        result.MediumMechanisms = entries.Count(e => e.Severity == PersistMechSeverity.Medium);
        result.LowMechanisms = entries.Count(e => e.Severity == PersistMechSeverity.Low);

        // Build chains
        result.Chains = BuildChains(entries);

        // Compute stats
        result.Stats = ComputeStats(entries);

        // Score and classify
        result.ThreatScore = ComputeThreatScore(entries, result.Chains);
        result.ThreatLevel = result.ThreatScore switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Moderate",
            >= 20 => "Low",
            _ => "Minimal"
        };

        // Recommendations
        result.Recommendations = GenerateRecommendations(result);

        return result;
    }

    private List<PersistMechEntry> DetectPersistence(Finding finding, string module)
    {
        var entries = new List<PersistMechEntry>();
        var text = $"{finding.Title} {finding.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            var matchedKeywords = sig.Keywords.Where(k => text.Contains(k.ToLowerInvariant())).ToList();
            if (matchedKeywords.Count == 0) continue;

            var confidence = sig.BaseConfidence * Math.Min(1.0, 0.6 + matchedKeywords.Count * 0.15);
            var isActive = ActivityIndicators.Any(a => text.Contains(a));
            var isDormant = DormancyIndicators.Any(d => text.Contains(d));

            // If both active and dormant indicators present, prefer active
            if (isActive && isDormant) isDormant = false;

            var severity = DetermineSeverity(sig, confidence, isActive, finding.Severity);

            entries.Add(new PersistMechEntry
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                Location = sig.Category,
                AssociatedUser = ExtractUser(text),
                ProcessName = ExtractProcess(text),
                DetectedAt = finding.Timestamp,
                Confidence = Math.Round(confidence, 3),
                Evidence = finding.Title,
                Severity = severity,
                IsActive = isActive,
                IsDormant = isDormant,
                Indicators = matchedKeywords,
                Category = module
            });
        }

        return entries;
    }

    private List<PersistMechEntry> DetectFromRecord(FindingRecord record)
    {
        var entries = new List<PersistMechEntry>();
        var text = $"{record.Title} {record.Description}".ToLowerInvariant();

        foreach (var sig in Signatures)
        {
            var matchedKeywords = sig.Keywords.Where(k => text.Contains(k.ToLowerInvariant())).ToList();
            if (matchedKeywords.Count == 0) continue;

            var confidence = sig.BaseConfidence * Math.Min(1.0, 0.6 + matchedKeywords.Count * 0.15);
            var isActive = ActivityIndicators.Any(a => text.Contains(a));
            var isDormant = DormancyIndicators.Any(d => text.Contains(d));
            if (isActive && isDormant) isDormant = false;

            var recordSeverity = record.Severity.ToLowerInvariant() switch
            {
                "critical" => Severity.Critical,
                "warning" => Severity.Warning,
                _ => Severity.Info
            };

            var severity = DetermineSeverity(sig, confidence, isActive, recordSeverity);

            entries.Add(new PersistMechEntry
            {
                Technique = sig.Name,
                MitreTechnique = sig.MitreId,
                Location = sig.Category,
                AssociatedUser = ExtractUser(text),
                ProcessName = ExtractProcess(text),
                DetectedAt = DateTimeOffset.UtcNow.AddDays(-1),
                Confidence = Math.Round(confidence, 3),
                Evidence = record.Title,
                Severity = severity,
                IsActive = isActive,
                IsDormant = isDormant,
                Indicators = matchedKeywords,
                Category = "Historical"
            });
        }

        return entries;
    }

    private static PersistMechSeverity DetermineSeverity(PersistTechniqueSignature sig,
        double confidence, bool isActive, Severity findingSeverity)
    {
        // Base severity from finding
        var baseSev = findingSeverity switch
        {
            Severity.Critical => 4,
            Severity.Warning => 3,
            Severity.Info => 2,
            _ => 1
        };

        // Boost for high confidence
        if (confidence >= 0.9) baseSev++;
        // Boost for active mechanisms
        if (isActive) baseSev++;
        // Certain techniques are inherently more dangerous
        if (sig.MitreId is "T1546.003" or "T1546.012" or "T1546.010") baseSev++;

        return baseSev switch
        {
            >= 5 => PersistMechSeverity.Critical,
            4 => PersistMechSeverity.High,
            3 => PersistMechSeverity.Medium,
            _ => PersistMechSeverity.Low
        };
    }

    private static List<PersistMechChain> BuildChains(List<PersistMechEntry> entries)
    {
        if (entries.Count < 2) return new();

        var chains = new List<PersistMechChain>();

        // Group by approximate time windows (within 24 hours)
        var sorted = entries.OrderBy(e => e.DetectedAt).ToList();
        var used = new HashSet<int>();

        for (var i = 0; i < sorted.Count; i++)
        {
            if (used.Contains(i)) continue;

            var chain = new List<PersistMechEntry> { sorted[i] };
            used.Add(i);

            for (var j = i + 1; j < sorted.Count; j++)
            {
                if (used.Contains(j)) continue;
                if (sorted[j].DetectedAt - sorted[i].DetectedAt > TimeSpan.FromHours(24)) break;
                if (sorted[j].Technique == sorted[i].Technique) continue; // Different techniques = chain

                chain.Add(sorted[j]);
                used.Add(j);
            }

            if (chain.Count >= 2)
            {
                var compoundConfidence = chain.Aggregate(1.0, (acc, e) => acc * e.Confidence);
                var depth = chain.Select(e => e.MitreTechnique).Distinct().Count();

                chains.Add(new PersistMechChain
                {
                    Mechanisms = chain,
                    PrimaryTechnique = chain.OrderByDescending(e => e.Confidence).First().Technique,
                    Depth = depth,
                    CompoundConfidence = Math.Round(compoundConfidence, 4),
                    Verdict = depth >= 4 ? "Advanced persistent threat — multi-layer persistence"
                        : depth >= 3 ? "Sophisticated attacker — layered persistence"
                        : "Potential multi-technique persistence",
                    DefenseInDepthLevel = depth >= 4 ? "Extreme" : depth >= 3 ? "High" : "Moderate"
                });
            }
        }

        return chains;
    }

    private static PersistMechStats ComputeStats(List<PersistMechEntry> entries)
    {
        if (entries.Count == 0)
            return new PersistMechStats();

        var techniques = entries.Select(e => e.Technique).Distinct().ToList();
        var locations = entries.Select(e => e.Location).Distinct().ToList();
        var techniqueGroups = entries.GroupBy(e => e.Technique).OrderByDescending(g => g.Count()).ToList();

        return new PersistMechStats
        {
            UniqueTechniquesUsed = techniques.Count,
            UniqueLocations = locations.Count,
            MostCommonTechnique = techniqueGroups.First().Key,
            AverageConfidence = Math.Round(entries.Average(e => e.Confidence), 3),
            DormancyRatio = entries.Count > 0 ? Math.Round((double)entries.Count(e => e.IsDormant) / entries.Count, 3) : 0,
            CrossTechniqueChains = 0,
            TechniqueDiversity = Math.Round((double)techniques.Count / Signatures.Count, 3)
        };
    }

    private static int ComputeThreatScore(List<PersistMechEntry> entries, List<PersistMechChain> chains)
    {
        if (entries.Count == 0) return 0;

        double score = 0;

        // Points per mechanism by severity
        foreach (var e in entries)
        {
            score += e.Severity switch
            {
                PersistMechSeverity.Critical => 15,
                PersistMechSeverity.High => 10,
                PersistMechSeverity.Medium => 5,
                PersistMechSeverity.Low => 2,
                _ => 1
            };

            // Bonus for active mechanisms
            if (e.IsActive) score += 3;
        }

        // Bonus for technique diversity
        var uniqueTechniques = entries.Select(e => e.MitreTechnique).Distinct().Count();
        score += uniqueTechniques * 4;

        // Bonus for chains
        score += chains.Sum(c => c.Depth * 5);

        return Math.Min(100, (int)score);
    }

    private static List<string> GenerateRecommendations(PersistMechReport report)
    {
        var recs = new List<string>();

        if (report.MechanismsDetected == 0)
        {
            recs.Add("No persistence mechanisms detected — continue regular monitoring.");
            return recs;
        }

        if (report.CriticalMechanisms > 0)
            recs.Add("URGENT: Investigate critical persistence mechanisms immediately — possible active compromise.");

        if (report.Entries.Any(e => e.MitreTechnique == "T1546.003"))
            recs.Add("Review WMI event subscriptions: Get-WMIObject -Namespace root\\Subscription -Class __EventFilter");

        if (report.Entries.Any(e => e.MitreTechnique == "T1547.001"))
            recs.Add("Audit registry Run keys and startup folder items with Autoruns or Get-ItemProperty HKLM:\\...\\Run");

        if (report.Entries.Any(e => e.MitreTechnique == "T1053.005"))
            recs.Add("Review scheduled tasks: schtasks /query /fo LIST /v — look for unusual task actions");

        if (report.Entries.Any(e => e.MitreTechnique == "T1543.003"))
            recs.Add("Audit Windows services for suspicious binpaths: Get-Service | Where-Object {$_.StartType -ne 'Disabled'}");

        if (report.Entries.Any(e => e.MitreTechnique == "T1546.012"))
            recs.Add("Check Image File Execution Options for debugger keys: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'");

        if (report.Entries.Any(e => e.MitreTechnique == "T1546.010"))
            recs.Add("Verify AppInit_DLLs is empty or disabled: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' /v AppInit_DLLs");

        if (report.Entries.Any(e => e.MitreTechnique == "T1176"))
            recs.Add("Review browser extension policies and installed extensions for unauthorized entries");

        if (report.Chains.Count > 0)
            recs.Add($"Detected {report.Chains.Count} multi-technique persistence chain(s) — indicates sophisticated attacker; consider full incident response.");

        if (report.ActiveMechanisms > report.DormantMechanisms)
            recs.Add("Majority of persistence mechanisms are active — prioritize immediate containment.");

        if (report.Stats.TechniqueDiversity >= 0.5)
            recs.Add("High technique diversity detected — attacker using multiple persistence vectors for redundancy.");

        return recs;
    }

    private static string? ExtractUser(string text)
    {
        var userPatterns = new[] { "system", "administrator", "nt authority", "network service", "local service" };
        foreach (var p in userPatterns)
            if (text.Contains(p)) return p.ToUpperInvariant();
        return null;
    }

    private static string? ExtractProcess(string text)
    {
        var processPatterns = new[] { "powershell", "cmd.exe", "wmic", "schtasks", "sc.exe", "reg.exe", "mshta", "rundll32", "regsvr32" };
        foreach (var p in processPatterns)
            if (text.Contains(p)) return p;
        return null;
    }

    /// <summary>Signature definition for a persistence technique.</summary>
    private sealed record PersistTechniqueSignature(
        string Name, string MitreId, string[] Keywords,
        double BaseConfidence, string Category);
}
