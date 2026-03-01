using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Analyzes finding persistence across audit runs to identify chronic issues,
/// calculate mean time to resolve (MTTR), and prioritize remediation efforts.
/// </summary>
public class FindingAgeTracker
{
    /// <summary>
    /// Analyze finding lifecycles from audit run history.
    /// Findings are matched by title + module name across runs.
    /// </summary>
    /// <param name="runs">Audit run records with findings loaded, ordered newest-first.</param>
    /// <returns>Complete age analysis report.</returns>
    public FindingAgeReport Analyze(IReadOnlyList<AuditRunRecord> runs)
    {
        if (runs == null) throw new ArgumentNullException(nameof(runs));

        var report = new FindingAgeReport();

        if (runs.Count == 0)
        {
            report.Summary = BuildSummary(report.Findings, 0);
            return report;
        }

        // Sort runs oldest-first for chronological processing
        var chronological = runs.OrderBy(r => r.Timestamp).ToList();

        // Track finding lifecycles by composite key (module + title)
        var lifecycles = new Dictionary<string, FindingLifecycle>(StringComparer.OrdinalIgnoreCase);

        // Track which findings appeared in each run
        var latestRunFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < chronological.Count; i++)
        {
            var run = chronological[i];
            var runFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var finding in run.Findings)
            {
                // Skip Pass-severity findings — they represent checks that passed
                if (finding.Severity.Equals("Pass", StringComparison.OrdinalIgnoreCase))
                    continue;

                var key = MakeKey(finding.ModuleName, finding.Title);
                runFindings.Add(key);

                if (lifecycles.TryGetValue(key, out var lifecycle))
                {
                    // Update existing lifecycle
                    lifecycle.LastSeen = run.Timestamp;
                    lifecycle.TotalOccurrences++;
                    lifecycle.Severity = finding.Severity; // Use latest severity
                    lifecycle.ConsecutiveRuns++;
                    lifecycle.IsActive = true;
                    lifecycle.ResolvedAt = null;
                }
                else
                {
                    // New finding
                    lifecycles[key] = new FindingLifecycle
                    {
                        Title = finding.Title,
                        ModuleName = finding.ModuleName,
                        Severity = finding.Severity,
                        FirstSeen = run.Timestamp,
                        LastSeen = run.Timestamp,
                        TotalOccurrences = 1,
                        ConsecutiveRuns = 1,
                        IsActive = true,
                        TotalRunsAnalyzed = chronological.Count
                    };
                }
            }

            // Mark findings that disappeared in this run as resolved
            foreach (var kvp in lifecycles)
            {
                if (kvp.Value.IsActive && !runFindings.Contains(kvp.Key))
                {
                    kvp.Value.IsActive = false;
                    kvp.Value.ResolvedAt = run.Timestamp;
                    kvp.Value.ConsecutiveRuns = 0;
                }
            }

            // Track latest run's findings for final active state
            if (i == chronological.Count - 1)
            {
                latestRunFindings = runFindings;
            }
        }

        // Set TotalRunsAnalyzed on all lifecycles
        foreach (var lc in lifecycles.Values)
        {
            lc.TotalRunsAnalyzed = chronological.Count;
        }

        report.Findings = lifecycles.Values.ToList();
        report.Summary = BuildSummary(report.Findings, chronological.Count);

        return report;
    }

    /// <summary>
    /// Format the analysis report as a human-readable text string.
    /// </summary>
    public string FormatReport(FindingAgeReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var lines = new List<string>();

        // Header
        lines.Add("═══════════════════════════════════════════════════");
        lines.Add("  Finding Age Tracker — Persistence Analysis");
        lines.Add("═══════════════════════════════════════════════════");
        lines.Add("");

        var s = report.Summary;

        // Overview
        lines.Add($"  Runs Analyzed:   {s.RunsAnalyzed}");
        lines.Add($"  Unique Findings: {s.TotalFindings}");
        lines.Add($"  Active:          {s.ActiveFindings}");
        lines.Add($"  Resolved:        {s.ResolvedFindings}");
        lines.Add($"  Chronic:         {s.ChronicFindings}");
        lines.Add($"  New:             {s.NewFindings}");
        lines.Add($"  Health Grade:    {s.HealthGrade}");
        lines.Add("");

        // MTTR stats
        if (s.MeanTimeToResolveHours.HasValue)
        {
            lines.Add("  Resolution Metrics:");
            lines.Add($"    Mean TTR:   {FormatHours(s.MeanTimeToResolveHours.Value)}");
            if (s.MedianTimeToResolveHours.HasValue)
                lines.Add($"    Median TTR: {FormatHours(s.MedianTimeToResolveHours.Value)}");
            lines.Add("");
        }

        if (s.OldestActiveFindingTitle != null)
        {
            lines.Add($"  Oldest Active: {s.OldestActiveFindingTitle}");
            lines.Add($"                 ({FormatHours(s.OldestActiveFindingHours!.Value)})");
            lines.Add("");
        }

        // Priority queue (top 10)
        var priority = report.PriorityQueue;
        if (priority.Count > 0)
        {
            lines.Add("  ┌─ Priority Queue (fix these first) ─────────────");
            var top = priority.Take(10).ToList();
            for (int i = 0; i < top.Count; i++)
            {
                var f = top[i];
                var severityIcon = GetSeverityIcon(f.Severity);
                lines.Add($"  │ {i + 1,2}. {severityIcon} {f.Title}");
                lines.Add($"  │      Module: {f.ModuleName} | Age: {f.AgeText} | Runs: {f.ConsecutiveRuns} | {f.Classification}");
            }
            lines.Add($"  └────────────────────────────────────────────────");
            lines.Add("");
        }

        // Chronic findings
        var chronic = report.ChronicFindings;
        if (chronic.Count > 0)
        {
            lines.Add("  ⚠ Chronic Findings (appear in 90%+ of runs):");
            foreach (var f in chronic)
            {
                lines.Add($"    • {f.Title} ({f.ModuleName}) — {f.TotalOccurrences}/{f.TotalRunsAnalyzed} runs, {f.AgeText}");
            }
            lines.Add("");
        }

        // New findings
        var newFindings = report.NewFindings;
        if (newFindings.Count > 0)
        {
            lines.Add("  🆕 New Findings:");
            foreach (var f in newFindings)
            {
                lines.Add($"    • {GetSeverityIcon(f.Severity)} {f.Title} ({f.ModuleName})");
            }
            lines.Add("");
        }

        // Recently resolved
        var resolved = report.ResolvedFindings.Take(5).ToList();
        if (resolved.Count > 0)
        {
            lines.Add("  ✅ Recently Resolved:");
            foreach (var f in resolved)
            {
                var ttl = f.ResolvedAt.HasValue
                    ? FormatHours((f.ResolvedAt.Value - f.FirstSeen).TotalHours)
                    : "unknown";
                lines.Add($"    • {f.Title} — lived {ttl}");
            }
            lines.Add("");
        }

        // Severity breakdown
        if (s.ActiveBySeverity.Count > 0)
        {
            lines.Add("  Active by Severity:");
            foreach (var kvp in s.ActiveBySeverity.OrderByDescending(x => SeverityOrder(x.Key)))
            {
                lines.Add($"    {GetSeverityIcon(kvp.Key)} {kvp.Key}: {kvp.Value}");
            }
            lines.Add("");
        }

        // Module breakdown
        if (s.ActiveByModule.Count > 0)
        {
            lines.Add("  Active by Module:");
            foreach (var kvp in s.ActiveByModule.OrderByDescending(x => x.Value))
            {
                lines.Add($"    {kvp.Key}: {kvp.Value}");
            }
            lines.Add("");
        }

        lines.Add(s.SummaryText);

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Serialize the report to a dictionary for JSON output.
    /// </summary>
    public Dictionary<string, object?> ToDict(FindingAgeReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        return new Dictionary<string, object?>
        {
            ["summary"] = new Dictionary<string, object?>
            {
                ["totalFindings"] = report.Summary.TotalFindings,
                ["activeFindings"] = report.Summary.ActiveFindings,
                ["resolvedFindings"] = report.Summary.ResolvedFindings,
                ["chronicFindings"] = report.Summary.ChronicFindings,
                ["newFindings"] = report.Summary.NewFindings,
                ["meanTimeToResolveHours"] = report.Summary.MeanTimeToResolveHours,
                ["medianTimeToResolveHours"] = report.Summary.MedianTimeToResolveHours,
                ["oldestActiveFindingHours"] = report.Summary.OldestActiveFindingHours,
                ["oldestActiveFindingTitle"] = report.Summary.OldestActiveFindingTitle,
                ["averageActiveAgeHours"] = report.Summary.AverageActiveAgeHours,
                ["runsAnalyzed"] = report.Summary.RunsAnalyzed,
                ["healthGrade"] = report.Summary.HealthGrade,
                ["activeBySeverity"] = report.Summary.ActiveBySeverity,
                ["activeByClassification"] = report.Summary.ActiveByClassification,
                ["activeByModule"] = report.Summary.ActiveByModule,
            },
            ["priorityQueue"] = report.PriorityQueue.Select(LifecycleToDict).ToList(),
            ["chronicFindings"] = report.ChronicFindings.Select(LifecycleToDict).ToList(),
            ["newFindings"] = report.NewFindings.Select(LifecycleToDict).ToList(),
            ["resolvedFindings"] = report.ResolvedFindings.Select(LifecycleToDict).ToList(),
            ["allFindings"] = report.Findings.Select(LifecycleToDict).ToList(),
        };
    }

    // ── Private helpers ──────────────────────────────────

    private static string MakeKey(string module, string title) => $"{module}::{title}";

    private FindingAgeSummary BuildSummary(List<FindingLifecycle> findings, int runsAnalyzed)
    {
        var active = findings.Where(f => f.IsActive).ToList();
        var resolved = findings.Where(f => !f.IsActive).ToList();
        var chronic = active.Where(f => f.Classification == "Chronic").ToList();
        var newFindings = active.Where(f => f.Classification == "New").ToList();

        var summary = new FindingAgeSummary
        {
            TotalFindings = findings.Count,
            ActiveFindings = active.Count,
            ResolvedFindings = resolved.Count,
            ChronicFindings = chronic.Count,
            NewFindings = newFindings.Count,
            RunsAnalyzed = runsAnalyzed,
        };

        // MTTR calculation
        var resolvedWithTime = resolved
            .Where(f => f.ResolvedAt.HasValue)
            .Select(f => (f.ResolvedAt!.Value - f.FirstSeen).TotalHours)
            .Where(h => h >= 0)
            .OrderBy(h => h)
            .ToList();

        if (resolvedWithTime.Count > 0)
        {
            summary.MeanTimeToResolveHours = resolvedWithTime.Average();
            summary.MedianTimeToResolveHours = Median(resolvedWithTime);
        }

        // Oldest active
        if (active.Count > 0)
        {
            var oldest = active.OrderByDescending(f => f.Age).First();
            summary.OldestActiveFindingHours = oldest.Age.TotalHours;
            summary.OldestActiveFindingTitle = oldest.Title;
            summary.AverageActiveAgeHours = active.Average(f => f.Age.TotalHours);
        }

        // Breakdowns
        summary.ActiveBySeverity = active
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        summary.ActiveByClassification = active
            .GroupBy(f => f.Classification)
            .ToDictionary(g => g.Key, g => g.Count());

        summary.ActiveByModule = active
            .GroupBy(f => f.ModuleName)
            .ToDictionary(g => g.Key, g => g.Count());

        // Health grade
        summary.HealthGrade = CalculateHealthGrade(summary, findings.Count);

        // Summary text
        summary.SummaryText = GenerateSummaryText(summary);

        return summary;
    }

    private static string CalculateHealthGrade(FindingAgeSummary summary, int totalFindings)
    {
        if (totalFindings == 0) return "A";

        // Score starts at 100, deductions for bad patterns
        double score = 100;

        // Chronic ratio penalty (0-30 points)
        if (summary.ActiveFindings > 0)
        {
            var chronicRatio = (double)summary.ChronicFindings / summary.ActiveFindings;
            score -= chronicRatio * 30;
        }

        // Active finding density penalty (0-25 points)
        var activeDensity = Math.Min((double)summary.ActiveFindings / Math.Max(summary.RunsAnalyzed, 1), 1.0);
        score -= activeDensity * 25;

        // MTTR penalty — longer MTTR = worse (0-20 points)
        if (summary.MeanTimeToResolveHours.HasValue)
        {
            var mttrPenalty = Math.Min(summary.MeanTimeToResolveHours.Value / 168.0, 1.0); // 168h = 1 week
            score -= mttrPenalty * 20;
        }

        // Resolution rate bonus (0-15 points back)
        if (totalFindings > 0)
        {
            var resolutionRate = (double)summary.ResolvedFindings / totalFindings;
            score += resolutionRate * 15;
        }

        // Critical chronic findings extra penalty (0-10 points)
        // Can't easily compute here without finding list, but we can
        // approximate from the severity breakdown
        if (summary.ActiveBySeverity.TryGetValue("Critical", out var critCount))
        {
            score -= Math.Min(critCount * 3.0, 10);
        }

        score = Math.Clamp(score, 0, 100);

        return score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
    }

    private static string GenerateSummaryText(FindingAgeSummary summary)
    {
        var parts = new List<string>();

        if (summary.ActiveFindings == 0 && summary.ResolvedFindings > 0)
        {
            parts.Add("All findings have been resolved. Excellent security posture.");
        }
        else if (summary.ActiveFindings == 0)
        {
            parts.Add("No findings to track.");
        }
        else
        {
            if (summary.ChronicFindings > 0)
            {
                parts.Add($"{summary.ChronicFindings} chronic finding(s) need attention — these have persisted across 90%+ of audit runs.");
            }
            if (summary.NewFindings > 0)
            {
                parts.Add($"{summary.NewFindings} new finding(s) appeared in the latest run.");
            }
            if (summary.MeanTimeToResolveHours.HasValue)
            {
                parts.Add($"Average resolution time: {FormatHours(summary.MeanTimeToResolveHours.Value)}.");
            }
            if (summary.OldestActiveFindingHours.HasValue && summary.OldestActiveFindingHours.Value > 168)
            {
                parts.Add($"Oldest active finding is {FormatHours(summary.OldestActiveFindingHours.Value)} old — consider prioritizing it.");
            }
        }

        return string.Join(" ", parts);
    }

    private static double Median(List<double> sorted)
    {
        if (sorted.Count == 0) return 0;
        int mid = sorted.Count / 2;
        return sorted.Count % 2 == 0
            ? (sorted[mid - 1] + sorted[mid]) / 2.0
            : sorted[mid];
    }

    private static string FormatHours(double hours)
    {
        if (hours >= 24)
        {
            var days = hours / 24;
            return $"{days:F1}d";
        }
        if (hours >= 1)
        {
            return $"{hours:F1}h";
        }
        return $"{hours * 60:F0}m";
    }

    private static string GetSeverityIcon(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => "🔴",
        "WARNING" => "🟡",
        "INFO" => "🔵",
        "PASS" => "🟢",
        _ => "⚪"
    };

    private static int SeverityOrder(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => 3,
        "WARNING" => 2,
        "INFO" => 1,
        _ => 0
    };

    private static Dictionary<string, object?> LifecycleToDict(FindingLifecycle lc) => new()
    {
        ["title"] = lc.Title,
        ["moduleName"] = lc.ModuleName,
        ["severity"] = lc.Severity,
        ["firstSeen"] = lc.FirstSeen.ToString("o"),
        ["lastSeen"] = lc.LastSeen.ToString("o"),
        ["resolvedAt"] = lc.ResolvedAt?.ToString("o"),
        ["consecutiveRuns"] = lc.ConsecutiveRuns,
        ["totalOccurrences"] = lc.TotalOccurrences,
        ["totalRunsAnalyzed"] = lc.TotalRunsAnalyzed,
        ["isActive"] = lc.IsActive,
        ["ageText"] = lc.AgeText,
        ["frequency"] = Math.Round(lc.Frequency, 3),
        ["priorityScore"] = Math.Round(lc.PriorityScore, 2),
        ["classification"] = lc.Classification,
    };
}
