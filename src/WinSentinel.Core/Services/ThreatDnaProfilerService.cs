namespace WinSentinel.Core.Services;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Threat DNA Profiler — analyzes a system's historical security audit
/// findings to generate a unique vulnerability fingerprint ("threat DNA"). Each
/// recurring finding pattern becomes a "gene" in the DNA, revealing which attack
/// categories, MITRE techniques, and vulnerability patterns the system is most
/// susceptible to. Tracks evolutionary changes over time and generates targeted
/// hardening recommendations.
///
/// MITRE ATT&CK coverage: Maps findings to techniques across Initial Access,
/// Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access,
/// Discovery, Lateral Movement, and Collection tactics.
/// </summary>
public sealed class ThreatDnaProfilerService
{
    private readonly AuditHistoryService _history;
    private readonly string _snapshotDir;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Module name to MITRE ATT&amp;CK technique mapping.
    /// </summary>
    public static readonly Dictionary<string, string> MitreMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Account"] = "T1078 — Valid Accounts",
        ["Network"] = "T1046 — Network Service Scanning",
        ["Firewall"] = "T1562.004 — Disable or Modify System Firewall",
        ["Encryption"] = "T1573 — Encrypted Channel",
        ["Process"] = "T1055 — Process Injection",
        ["Service"] = "T1543.003 — Windows Service",
        ["Browser"] = "T1185 — Browser Session Hijacking",
        ["Certificate"] = "T1553.004 — Install Root Certificate",
        ["Registry"] = "T1112 — Modify Registry",
        ["ScheduledTask"] = "T1053.005 — Scheduled Task",
        ["Startup"] = "T1547.001 — Registry Run Keys / Startup Folder",
        ["Update"] = "T1195.002 — Compromise Software Supply Chain",
        ["Defender"] = "T1562.001 — Disable or Modify Tools",
        ["RemoteAccess"] = "T1021 — Remote Services",
        ["Credential"] = "T1003 — OS Credential Dumping",
        ["Privacy"] = "T1119 — Automated Collection",
        ["Driver"] = "T1068 — Exploitation for Privilege Escalation",
        ["PowerShell"] = "T1059.001 — PowerShell",
        ["Wifi"] = "T1557 — Adversary-in-the-Middle",
        ["Bluetooth"] = "T1011 — Exfiltration Over Other Network Medium",
        ["SMB"] = "T1021.002 — SMB/Windows Admin Shares",
        ["DNS"] = "T1071.004 — DNS",
        ["GroupPolicy"] = "T1484.001 — Group Policy Modification",
        ["EventLog"] = "T1070.001 — Clear Windows Event Logs",
        ["Virtualization"] = "T1497 — Virtualization/Sandbox Evasion",
        ["Backup"] = "T1490 — Inhibit System Recovery",
        ["Software"] = "T1072 — Software Deployment Tools",
        ["System"] = "T1082 — System Information Discovery",
        ["AppSecurity"] = "T1218 — System Binary Proxy Execution",
        ["Clipboard"] = "T1115 — Clipboard Data",
        ["FileSystem"] = "T1083 — File and Directory Discovery",
    };

    /// <summary>Severity weight for scoring.</summary>
    public static int SeverityWeight(string severity) => severity?.ToLowerInvariant() switch
    {
        "critical" => 10,
        "warning" => 5,
        "info" => 1,
        _ => 0
    };

    public ThreatDnaProfilerService(AuditHistoryService history, string? snapshotDir = null)
    {
        _history = history;
        _snapshotDir = snapshotDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel", "dna");
    }

    /// <summary>
    /// Generate a full threat DNA profile from audit history.
    /// </summary>
    public ThreatDnaReport GenerateProfile(int historyDays = 90, int topN = 15)
    {
        var report = new ThreatDnaReport
        {
            SystemId = Environment.MachineName,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        // 1. Load history runs (lightweight, no findings)
        var runs = _history.GetHistory(historyDays);
        if (runs.Count == 0) return report;

        var ordered = runs.OrderBy(r => r.Timestamp).ToList();

        // 2. Load findings for each run
        var runFindings = new List<(DateTimeOffset Timestamp, List<FindingRecord> Findings)>();
        foreach (var run in ordered)
        {
            var details = _history.GetRunDetails(run.Id);
            if (details != null && details.Findings.Count > 0)
                runFindings.Add((run.Timestamp, details.Findings));
        }

        if (runFindings.Count == 0) return report;

        // 3. Build genes from findings
        var genes = BuildGenes(runFindings);
        report.Genes = genes
            .OrderByDescending(g => g.Frequency)
            .ThenByDescending(g => SeverityWeight(g.Severity))
            .Take(topN)
            .ToList();
        report.GeneCount = genes.Count;

        // 4. Build category breakdown
        report.CategoryBreakdown = BuildCategoryBreakdown(genes, runFindings);

        // 5. Set dominant category
        if (report.CategoryBreakdown.Count > 0)
            report.DominantCategory = report.CategoryBreakdown
                .OrderByDescending(c => c.ExposureScore)
                .First().Category;

        // 6. Calculate resilience score
        report.OverallResilienceScore = CalculateResilienceScore(genes);

        // 7. Compute DNA hash
        report.DnaHash = ComputeDnaHash(genes);

        // 8. Load previous snapshots and detect mutations
        var previousSnapshots = LoadSnapshots();
        var currentSnapshot = new DnaSnapshot
        {
            Timestamp = DateTimeOffset.UtcNow,
            GeneCount = genes.Count,
            ActiveGenes = genes.Count(g => g.IsActive),
            ResilienceScore = report.OverallResilienceScore,
            TopCategory = report.DominantCategory,
            DnaHash = report.DnaHash
        };

        if (previousSnapshots.Count > 0)
        {
            report.MutationAlerts = DetectMutations(previousSnapshots.Last(), genes, runFindings);
        }

        previousSnapshots.Add(currentSnapshot);
        report.EvolutionTimeline = previousSnapshots;

        // 9. Determine evolution phase
        report.EvolutionPhase = DetermineEvolutionPhase(previousSnapshots);

        // 10. Generate hardening plan
        report.HardeningPlan = GenerateHardeningPlan(genes);

        // 11. Generate recommendations
        report.Recommendations = GenerateRecommendations(report);

        // 12. Save snapshot
        SaveSnapshots(previousSnapshots);

        return report;
    }

    /// <summary>
    /// Get the stored evolution history without running a new analysis.
    /// </summary>
    public List<DnaSnapshot> GetEvolutionHistory() => LoadSnapshots();

    // ── Gene Building ────────────────────────────────────────────────

    private List<ThreatGene> BuildGenes(
        List<(DateTimeOffset Timestamp, List<FindingRecord> Findings)> runFindings)
    {
        var geneMap = new Dictionary<string, ThreatGene>(StringComparer.OrdinalIgnoreCase);
        var totalScans = runFindings.Count;

        // Track per-gene appearance counts and fix/return cycles
        var appearances = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var regressions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        HashSet<string>? previousSet = null;

        foreach (var (timestamp, findings) in runFindings)
        {
            var currentSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var finding in findings)
            {
                // Skip Pass/Info findings for DNA
                if (string.Equals(finding.Severity, "Pass", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(finding.Severity, "Info", StringComparison.OrdinalIgnoreCase))
                    continue;

                var key = $"{finding.ModuleName}|{finding.Title}";
                currentSet.Add(key);

                if (!geneMap.ContainsKey(key))
                {
                    var category = DeriveCategory(finding.ModuleName);
                    var geneId = GenerateGeneId(category, geneMap.Count);
                    geneMap[key] = new ThreatGene
                    {
                        GeneId = geneId,
                        Category = category,
                        MitreTechnique = MapToMitre(finding.ModuleName),
                        Title = finding.Title,
                        Severity = finding.Severity,
                        FirstSeen = timestamp,
                        LastSeen = timestamp,
                        Frequency = 0,
                        IsActive = false
                    };
                    appearances[key] = 0;
                    regressions[key] = 0;
                }

                geneMap[key].LastSeen = timestamp;
                geneMap[key].Frequency++;
                appearances[key]++;

                // Detect regression (was absent, now back)
                if (previousSet != null && !previousSet.Contains(key) && appearances[key] > 1)
                    regressions[key]++;
            }

            previousSet = currentSet;
        }

        // Mark active genes (present in last scan)
        var lastFindings = runFindings.Last().Findings;
        var lastSet = new HashSet<string>(
            lastFindings
                .Where(f => !string.Equals(f.Severity, "Pass", StringComparison.OrdinalIgnoreCase) &&
                            !string.Equals(f.Severity, "Info", StringComparison.OrdinalIgnoreCase))
                .Select(f => $"{f.ModuleName}|{f.Title}"),
            StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in geneMap)
        {
            kvp.Value.IsActive = lastSet.Contains(kvp.Key);
            kvp.Value.Persistence = totalScans > 0
                ? Math.Round((double)appearances[kvp.Key] / totalScans, 3)
                : 0;
            kvp.Value.ResistanceScore = appearances[kvp.Key] > 1
                ? Math.Round((double)regressions[kvp.Key] / (appearances[kvp.Key] - 1), 3)
                : 0;
        }

        return geneMap.Values.ToList();
    }

    private static string DeriveCategory(string moduleName)
    {
        if (string.IsNullOrEmpty(moduleName)) return "Unknown";

        // Strip common suffixes
        var name = moduleName.Replace("Audit", "", StringComparison.OrdinalIgnoreCase)
                             .Replace("Monitor", "", StringComparison.OrdinalIgnoreCase)
                             .Trim();

        return string.IsNullOrEmpty(name) ? "General" : name;
    }

    private static string GenerateGeneId(string category, int index)
    {
        var prefix = category.Length >= 3
            ? category[..3].ToUpperInvariant()
            : category.ToUpperInvariant().PadRight(3, 'X');
        return $"GENE-{prefix}-{index + 1:D3}";
    }

    private static string MapToMitre(string moduleName)
    {
        var category = moduleName.Replace("Audit", "", StringComparison.OrdinalIgnoreCase)
                                 .Replace("Monitor", "", StringComparison.OrdinalIgnoreCase)
                                 .Trim();

        if (MitreMap.TryGetValue(category, out var technique)) return technique;
        if (MitreMap.TryGetValue(moduleName, out technique)) return technique;
        return "T1082 — System Information Discovery";
    }

    // ── Category Breakdown ───────────────────────────────────────────

    private static List<DnaCategoryProfile> BuildCategoryBreakdown(
        List<ThreatGene> genes,
        List<(DateTimeOffset Timestamp, List<FindingRecord> Findings)> runFindings)
    {
        var categories = genes.GroupBy(g => g.Category).Select(grp =>
        {
            var catGenes = grp.ToList();
            var activeCount = catGenes.Count(g => g.IsActive);
            var maxSeverityWeight = catGenes.Max(g => SeverityWeight(g.Severity));
            var dominantSev = catGenes
                .OrderByDescending(g => SeverityWeight(g.Severity))
                .First().Severity;

            // Exposure = weighted active genes + persistence factor
            var exposure = Math.Min(100.0, catGenes.Sum(g =>
                SeverityWeight(g.Severity) * g.Persistence * (g.IsActive ? 2.0 : 0.5)));

            // Trend: compare first half vs second half of appearances
            var trend = "Stable";
            if (runFindings.Count >= 4)
            {
                var mid = runFindings.Count / 2;
                var firstHalf = runFindings.Take(mid).SelectMany(r => r.Findings)
                    .Count(f => catGenes.Any(g => g.Title == f.Title));
                var secondHalf = runFindings.Skip(mid).SelectMany(r => r.Findings)
                    .Count(f => catGenes.Any(g => g.Title == f.Title));
                if (secondHalf > firstHalf * 1.3) trend = "Worsening";
                else if (secondHalf < firstHalf * 0.7) trend = "Improving";
            }

            return new DnaCategoryProfile
            {
                Category = grp.Key,
                GeneCount = catGenes.Count,
                ActiveGenes = activeCount,
                DominantSeverity = dominantSev,
                ExposureScore = Math.Round(exposure, 1),
                TrendDirection = trend
            };
        })
        .OrderByDescending(c => c.ExposureScore)
        .ToList();

        return categories;
    }

    // ── Resilience Score ─────────────────────────────────────────────

    public static int CalculateResilienceScore(List<ThreatGene> genes)
    {
        if (genes.Count == 0) return 100;

        var activeGenes = genes.Where(g => g.IsActive).ToList();
        if (activeGenes.Count == 0) return 95; // All genes eliminated

        var weightedImpact = activeGenes.Sum(g =>
            SeverityWeight(g.Severity) * (1 + g.Persistence) * (1 + g.ResistanceScore));

        // Normalize: assume max impact = 20 active critical genes at full persistence+resistance
        var maxImpact = 20.0 * 10 * 2.0 * 2.0;
        var normalized = Math.Min(1.0, weightedImpact / maxImpact);

        return Math.Max(0, Math.Min(100, (int)(100 * (1 - normalized))));
    }

    // ── DNA Hash ─────────────────────────────────────────────────────

    public static string ComputeDnaHash(List<ThreatGene> genes)
    {
        if (genes.Count == 0) return "0000000000000000";

        var sortedIds = genes
            .Where(g => g.IsActive)
            .Select(g => g.GeneId)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        if (sortedIds.Count == 0)
            sortedIds = genes.Select(g => g.GeneId).OrderBy(id => id, StringComparer.Ordinal).ToList();

        var payload = string.Join("|", sortedIds);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash)[..16].ToUpperInvariant();
    }

    // ── Mutation Detection ───────────────────────────────────────────

    private static List<DnaMutation> DetectMutations(
        DnaSnapshot previousSnapshot,
        List<ThreatGene> currentGenes,
        List<(DateTimeOffset Timestamp, List<FindingRecord> Findings)> runFindings)
    {
        var mutations = new List<DnaMutation>();
        var now = DateTimeOffset.UtcNow;

        // Gene count changes
        if (currentGenes.Count > previousSnapshot.GeneCount)
        {
            var newCount = currentGenes.Count - previousSnapshot.GeneCount;
            var newGenes = currentGenes
                .OrderByDescending(g => g.FirstSeen)
                .Take(newCount)
                .ToList();

            foreach (var gene in newGenes)
            {
                mutations.Add(new DnaMutation
                {
                    Timestamp = now,
                    MutationType = DnaMutationType.NewGene,
                    Description = $"New vulnerability pattern detected: {gene.Title}",
                    AffectedGene = gene.GeneId,
                    Impact = SeverityWeight(gene.Severity) >= 5 ? "High" : "Medium"
                });
            }
        }
        else if (currentGenes.Count < previousSnapshot.GeneCount)
        {
            mutations.Add(new DnaMutation
            {
                Timestamp = now,
                MutationType = DnaMutationType.GeneEliminated,
                Description = $"{previousSnapshot.GeneCount - currentGenes.Count} vulnerability pattern(s) eliminated",
                AffectedGene = "",
                Impact = "Positive"
            });
        }

        // Resurgence detection — genes with high resistance score
        foreach (var gene in currentGenes.Where(g => g.IsActive && g.ResistanceScore > 0.5))
        {
            mutations.Add(new DnaMutation
            {
                Timestamp = now,
                MutationType = DnaMutationType.Resurgence,
                Description = $"Recurring pattern: {gene.Title} keeps returning after fixes (resistance: {gene.ResistanceScore:P0})",
                AffectedGene = gene.GeneId,
                Impact = "High"
            });
        }

        // Category shift
        if (!string.IsNullOrEmpty(previousSnapshot.TopCategory))
        {
            var currentTop = currentGenes
                .Where(g => g.IsActive)
                .GroupBy(g => g.Category)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.Key ?? "";

            if (!string.IsNullOrEmpty(currentTop) &&
                !string.Equals(currentTop, previousSnapshot.TopCategory, StringComparison.OrdinalIgnoreCase))
            {
                mutations.Add(new DnaMutation
                {
                    Timestamp = now,
                    MutationType = DnaMutationType.CategoryShift,
                    Description = $"Dominant threat category shifted from {previousSnapshot.TopCategory} to {currentTop}",
                    AffectedGene = "",
                    Impact = "Medium"
                });
            }
        }

        // Severity escalation — genes that worsened
        foreach (var gene in currentGenes.Where(g => g.IsActive &&
            string.Equals(g.Severity, "Critical", StringComparison.OrdinalIgnoreCase) &&
            g.Persistence > 0.5))
        {
            mutations.Add(new DnaMutation
            {
                Timestamp = now,
                MutationType = DnaMutationType.SeverityEscalation,
                Description = $"Persistent critical pattern: {gene.Title} (persistence: {gene.Persistence:P0})",
                AffectedGene = gene.GeneId,
                Impact = "Critical"
            });
        }

        return mutations;
    }

    // ── Evolution Phase ──────────────────────────────────────────────

    public static string DetermineEvolutionPhase(List<DnaSnapshot> snapshots)
    {
        if (snapshots.Count < 2) return "Emerging";

        var recent = snapshots.TakeLast(Math.Min(5, snapshots.Count)).ToList();
        var scores = recent.Select(s => s.ResilienceScore).ToList();

        var avgScore = scores.Average();
        var trend = scores.Last() - scores.First();
        var activeGenesTrend = recent.Last().ActiveGenes - recent.First().ActiveGenes;

        if (avgScore >= 85 && trend >= 0 && activeGenesTrend <= 0) return "Resilient";
        if (trend > 5 && activeGenesTrend < 0) return "Hardening";
        if (Math.Abs(trend) <= 5) return "Stabilizing";
        return "Emerging";
    }

    // ── Hardening Plan ───────────────────────────────────────────────

    private static List<DnaHardeningAction> GenerateHardeningPlan(List<ThreatGene> genes)
    {
        var activeGenes = genes.Where(g => g.IsActive).ToList();
        if (activeGenes.Count == 0) return [];

        var plan = new List<DnaHardeningAction>();
        var priority = 1;

        // Group by category, prioritize by exposure
        var groups = activeGenes
            .GroupBy(g => g.Category)
            .OrderByDescending(g => g.Sum(gene => SeverityWeight(gene.Severity) * (1 + gene.ResistanceScore)))
            .ToList();

        foreach (var group in groups)
        {
            var catGenes = group.ToList();
            var criticals = catGenes.Where(g =>
                string.Equals(g.Severity, "Critical", StringComparison.OrdinalIgnoreCase)).ToList();
            var warnings = catGenes.Where(g =>
                string.Equals(g.Severity, "Warning", StringComparison.OrdinalIgnoreCase)).ToList();

            if (criticals.Count > 0)
            {
                plan.Add(new DnaHardeningAction
                {
                    Priority = priority++,
                    Action = $"Remediate {criticals.Count} critical {group.Key} finding(s) immediately",
                    TargetGenes = criticals.Select(g => g.GeneId).ToList(),
                    ExpectedImpact = $"Eliminate {criticals.Count} critical genes from threat DNA",
                    Effort = criticals.Count > 3 ? "High" : "Medium",
                    ResilienceGain = Math.Min(30, criticals.Count * 8)
                });
            }

            if (warnings.Count > 0)
            {
                var resistantWarnings = warnings.Where(w => w.ResistanceScore > 0.3).ToList();
                plan.Add(new DnaHardeningAction
                {
                    Priority = priority++,
                    Action = $"Harden {group.Key} configuration ({warnings.Count} warnings" +
                             (resistantWarnings.Count > 0 ? $", {resistantWarnings.Count} resistant to fixes)" : ")"),
                    TargetGenes = warnings.Select(g => g.GeneId).ToList(),
                    ExpectedImpact = $"Reduce {group.Key} exposure by up to {Math.Min(90, warnings.Count * 15)}%",
                    Effort = resistantWarnings.Count > 2 ? "High" : "Low",
                    ResilienceGain = Math.Min(20, warnings.Count * 4)
                });
            }

            if (priority > 10) break; // Cap at 10 actions
        }

        return plan;
    }

    // ── Recommendations ──────────────────────────────────────────────

    private static List<string> GenerateRecommendations(ThreatDnaReport report)
    {
        var recs = new List<string>();

        if (report.OverallResilienceScore < 50)
            recs.Add("URGENT: System resilience is critically low. Prioritize the hardening plan immediately.");

        var criticalGenes = report.Genes.Count(g => g.IsActive &&
            string.Equals(g.Severity, "Critical", StringComparison.OrdinalIgnoreCase));
        if (criticalGenes > 0)
            recs.Add($"Address {criticalGenes} active critical gene(s) to significantly improve resilience score.");

        var resistantGenes = report.Genes.Count(g => g.ResistanceScore > 0.5);
        if (resistantGenes > 0)
            recs.Add($"{resistantGenes} gene(s) show high fix resistance — investigate root causes rather than applying surface-level patches.");

        var worseningCats = report.CategoryBreakdown.Where(c => c.TrendDirection == "Worsening").ToList();
        if (worseningCats.Count > 0)
            recs.Add($"Categories trending worse: {string.Join(", ", worseningCats.Select(c => c.Category))}. Focus audit efforts here.");

        if (report.EvolutionPhase == "Emerging")
            recs.Add("Threat DNA is still forming — run more frequent audits to build a clear vulnerability baseline.");

        if (report.EvolutionPhase == "Resilient")
            recs.Add("System shows strong resilience. Continue monitoring for new gene mutations.");

        var highPersistence = report.Genes.Count(g => g.Persistence > 0.8 && g.IsActive);
        if (highPersistence > 0)
            recs.Add($"{highPersistence} gene(s) are nearly permanent fixtures — consider architectural changes or compensating controls.");

        if (recs.Count == 0)
            recs.Add("Threat DNA analysis complete. Continue regular scanning to track evolution.");

        return recs;
    }

    // ── Snapshot Persistence ─────────────────────────────────────────

    private List<DnaSnapshot> LoadSnapshots()
    {
        var path = Path.Combine(_snapshotDir, "snapshots.json");
        if (!File.Exists(path)) return [];

        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<DnaSnapshot>>(json, JsonOpts) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private void SaveSnapshots(List<DnaSnapshot> snapshots)
    {
        Directory.CreateDirectory(_snapshotDir);
        var path = Path.Combine(_snapshotDir, "snapshots.json");

        // Keep last 100 snapshots
        var toSave = snapshots.Count > 100 ? snapshots.TakeLast(100).ToList() : snapshots;
        File.WriteAllText(path, JsonSerializer.Serialize(toSave, JsonOpts));
    }
}
