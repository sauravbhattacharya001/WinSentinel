using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Detects "flapping" findings — those that alternate between present and absent
/// across audit runs, indicating unstable configuration or environmental drift.
/// </summary>
public class FlappingDetector
{
    /// <summary>Minimum flap rate to be considered flapping.</summary>
    private const double MinFlapRate = 0.2;

    /// <summary>
    /// Analyze audit run history and detect flapping findings.
    /// Runs should be ordered oldest-first or newest-first; the method sorts internally.
    /// </summary>
    public FlappingReport Analyze(List<AuditRunRecord> runs)
    {
        if (runs.Count < 3)
        {
            return new FlappingReport
            {
                HasData = false,
                Summary = new FlappingSummary
                {
                    RunsAnalyzed = runs.Count,
                    StabilityGrade = "N/A"
                }
            };
        }

        // Sort oldest first
        var sorted = runs.OrderBy(r => r.Timestamp).ToList();

        // Build a presence matrix: for each finding title, track which runs it appeared in
        var findingPresence = new Dictionary<string, List<bool>>();
        var findingMeta = new Dictionary<string, (string Module, string Severity, DateTimeOffset FirstSeen, DateTimeOffset LastSeen)>();

        foreach (var run in sorted)
        {
            var titlesInRun = new HashSet<string>(
                run.Findings?.Select(f => f.Title) ?? Enumerable.Empty<string>());

            // Update existing findings
            foreach (var title in findingPresence.Keys)
            {
                findingPresence[title].Add(titlesInRun.Contains(title));
            }

            // Add new findings
            foreach (var finding in run.Findings ?? [])
            {
                if (!findingPresence.ContainsKey(finding.Title))
                {
                    // Backfill with false for all previous runs
                    var history = new List<bool>();
                    for (int i = 0; i < sorted.IndexOf(run); i++)
                        history.Add(false);
                    history.Add(true);
                    findingPresence[finding.Title] = history;

                    findingMeta[finding.Title] = (
                        finding.ModuleName,
                        finding.Severity,
                        run.Timestamp,
                        run.Timestamp);
                }
                else
                {
                    var meta = findingMeta[finding.Title];
                    findingMeta[finding.Title] = (
                        finding.ModuleName,
                        finding.Severity,
                        meta.FirstSeen,
                        run.Timestamp);
                }
            }
        }

        // Calculate flapping metrics
        var flappingFindings = new List<FlappingFinding>();
        var totalRuns = sorted.Count;

        foreach (var (title, presence) in findingPresence)
        {
            // Count transitions
            int transitions = 0;
            for (int i = 1; i < presence.Count; i++)
            {
                if (presence[i] != presence[i - 1])
                    transitions++;
            }

            var presentCount = presence.Count(p => p);
            var absentCount = presence.Count(p => !p);
            var flapRate = totalRuns > 1 ? (double)transitions / (totalRuns - 1) : 0;

            if (flapRate < MinFlapRate) continue;

            var meta = findingMeta[title];

            // Build pattern string (last 20 runs max)
            var recentPresence = presence.TakeLast(20).ToList();
            var pattern = string.Join("", recentPresence.Select(p => p ? "█" : "░"));

            flappingFindings.Add(new FlappingFinding
            {
                Title = title,
                ModuleName = meta.Module,
                Severity = meta.Severity,
                Transitions = transitions,
                PresentCount = presentCount,
                AbsentCount = absentCount,
                TotalRuns = totalRuns,
                CurrentlyPresent = presence.Last(),
                FirstSeen = meta.FirstSeen,
                LastSeen = meta.LastSeen,
                Pattern = pattern
            });
        }

        // Sort by flap rate descending
        flappingFindings = flappingFindings
            .OrderByDescending(f => f.FlapRate)
            .ThenByDescending(f => f.Severity == "Critical" ? 2 : f.Severity == "Warning" ? 1 : 0)
            .ToList();

        // Build summary
        var summary = BuildSummary(flappingFindings, totalRuns, findingPresence.Count);

        return new FlappingReport
        {
            HasData = true,
            Findings = flappingFindings,
            Summary = summary
        };
    }

    private static FlappingSummary BuildSummary(List<FlappingFinding> findings, int totalRuns, int totalFindings)
    {
        var highlyUnstable = findings.Count(f => f.FlapRate >= 0.7);
        var unstable = findings.Count(f => f.FlapRate >= 0.4 && f.FlapRate < 0.7);
        var intermittent = findings.Count(f => f.FlapRate >= 0.2 && f.FlapRate < 0.4);

        var byModule = findings
            .GroupBy(f => f.ModuleName)
            .ToDictionary(g => g.Key, g => g.Count());

        var bySeverity = findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var mostUnstable = byModule.OrderByDescending(kv => kv.Value).FirstOrDefault();

        var avgFlapRate = findings.Count > 0
            ? findings.Average(f => f.FlapRate)
            : 0;

        // Grade based on ratio of flapping to total findings
        var flapRatio = totalFindings > 0 ? (double)findings.Count / totalFindings : 0;
        var grade = flapRatio switch
        {
            <= 0.05 => "A",
            <= 0.10 => "B",
            <= 0.20 => "C",
            <= 0.35 => "D",
            _ => "F"
        };

        return new FlappingSummary
        {
            TotalFindings = totalFindings,
            FlappingCount = findings.Count,
            HighlyUnstableCount = highlyUnstable,
            UnstableCount = unstable,
            IntermittentCount = intermittent,
            AverageFlapRate = Math.Round(avgFlapRate, 3),
            MostUnstableModule = mostUnstable.Key,
            MostUnstableModuleCount = mostUnstable.Value,
            RunsAnalyzed = totalRuns,
            StabilityGrade = grade,
            FlappingByModule = byModule,
            FlappingBySeverity = bySeverity
        };
    }

    /// <summary>
    /// Format the flapping report as console-friendly text.
    /// </summary>
    public static string FormatReport(FlappingReport report)
    {
        if (!report.HasData)
            return "  Not enough audit history (need 3+ runs). Run more audits first.";

        var lines = new List<string>();
        var s = report.Summary;

        lines.Add("");
        lines.Add("  ╔══════════════════════════════════════════════╗");
        lines.Add("  ║     ⚡ Flapping Detection Report             ║");
        lines.Add("  ╚══════════════════════════════════════════════╝");
        lines.Add("");
        lines.Add($"  Stability Grade:  {s.StabilityGrade}");
        lines.Add($"  Runs Analyzed:    {s.RunsAnalyzed}");
        lines.Add($"  Total Findings:   {s.TotalFindings}");
        lines.Add($"  Flapping:         {s.FlappingCount} ({(s.TotalFindings > 0 ? (100.0 * s.FlappingCount / s.TotalFindings).ToString("F1") : "0")}%)");
        lines.Add("");

        if (s.HighlyUnstableCount > 0)
            lines.Add($"    🔴 Highly Unstable:  {s.HighlyUnstableCount}");
        if (s.UnstableCount > 0)
            lines.Add($"    🟡 Unstable:         {s.UnstableCount}");
        if (s.IntermittentCount > 0)
            lines.Add($"    🔵 Intermittent:     {s.IntermittentCount}");

        if (s.MostUnstableModule != null)
        {
            lines.Add("");
            lines.Add($"  Most unstable module: {s.MostUnstableModule} ({s.MostUnstableModuleCount} flapping findings)");
        }

        if (report.Findings.Count > 0)
        {
            lines.Add("");
            lines.Add("  ──────────────────────────────────────────────────────────────────");
            lines.Add("  Finding                                    Flap%  Stability Pattern");
            lines.Add("  ──────────────────────────────────────────────────────────────────");

            foreach (var f in report.Findings.Take(25))
            {
                var title = f.Title.Length > 40 ? f.Title[..37] + "..." : f.Title;
                var icon = f.FlapRate >= 0.7 ? "🔴" : f.FlapRate >= 0.4 ? "🟡" : "🔵";
                lines.Add($"  {icon} {title,-40} {f.FlapRate * 100,5:F0}%  {f.StabilityScore,3}/100  {f.Pattern}");
            }

            if (report.Findings.Count > 25)
                lines.Add($"  ... and {report.Findings.Count - 25} more");
        }
        else
        {
            lines.Add("");
            lines.Add("  ✅ No flapping findings detected — your system is stable!");
        }

        lines.Add("");
        lines.Add("  Legend: █ = present  ░ = absent (across recent runs, left=oldest)");
        lines.Add("");

        return string.Join(Environment.NewLine, lines);
    }
}
