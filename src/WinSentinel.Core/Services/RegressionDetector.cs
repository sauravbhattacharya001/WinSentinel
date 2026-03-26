using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Detects security regressions — findings that were previously resolved but have reappeared.
/// Analyzes audit history to identify patterns of recurring issues that keep coming back.
/// </summary>
public class RegressionDetector
{
    /// <summary>
    /// Analyze audit history to find regressions (resolved findings that reappeared).
    /// </summary>
    public RegressionReport Analyze(List<AuditRunRecord> runs)
    {
        if (runs.Count < 2)
        {
            return new RegressionReport
            {
                HasData = false,
                Message = "Need at least 2 audit runs to detect regressions."
            };
        }

        // Sort runs oldest → newest
        var sorted = runs.OrderBy(r => r.Timestamp).ToList();

        var regressions = new List<RegressionFinding>();
        var resolvedTitles = new Dictionary<string, ResolvedInfo>();

        for (int i = 0; i < sorted.Count; i++)
        {
            var run = sorted[i];
            var currentTitles = new HashSet<string>(run.Findings.Select(f => f.Title));

            if (i > 0)
            {
                var prevRun = sorted[i - 1];
                var prevTitles = new HashSet<string>(prevRun.Findings.Select(f => f.Title));

                // Find newly resolved (was in prev, not in current)
                foreach (var f in prevRun.Findings)
                {
                    if (!currentTitles.Contains(f.Title))
                    {
                        resolvedTitles[f.Title] = new ResolvedInfo
                        {
                            ResolvedAt = run.Timestamp,
                            Severity = f.Severity,
                            ModuleName = f.ModuleName,
                            Description = f.Description,
                            Remediation = f.Remediation
                        };
                    }
                }

                // Find regressions (was resolved, now back)
                foreach (var f in run.Findings)
                {
                    if (resolvedTitles.TryGetValue(f.Title, out var info))
                    {
                        var existing = regressions.FirstOrDefault(r => r.Title == f.Title);
                        if (existing != null)
                        {
                            existing.RegressionCount++;
                            existing.LastRegressedAt = run.Timestamp;
                        }
                        else
                        {
                            regressions.Add(new RegressionFinding
                            {
                                Title = f.Title,
                                Severity = f.Severity,
                                ModuleName = f.ModuleName,
                                Description = f.Description,
                                Remediation = f.Remediation,
                                FirstResolvedAt = info.ResolvedAt,
                                LastRegressedAt = run.Timestamp,
                                RegressionCount = 1
                            });
                        }

                        // Remove from resolved tracking since it's back
                        resolvedTitles.Remove(f.Title);
                    }
                }
            }
        }

        // Sort by severity (critical first), then by regression count
        regressions = regressions
            .OrderByDescending(r => SeverityRank(r.Severity))
            .ThenByDescending(r => r.RegressionCount)
            .ToList();

        var latestRun = sorted.Last();

        return new RegressionReport
        {
            HasData = true,
            AnalyzedRuns = sorted.Count,
            AnalyzedDays = (int)(sorted.Last().Timestamp - sorted.First().Timestamp).TotalDays,
            FirstRunDate = sorted.First().Timestamp,
            LastRunDate = sorted.Last().Timestamp,
            Regressions = regressions,
            TotalRegressions = regressions.Count,
            CriticalRegressions = regressions.Count(r => r.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
            WarningRegressions = regressions.Count(r => r.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase)),
            RepeatOffenders = regressions.Where(r => r.RegressionCount >= 2).ToList(),
            // Findings in the latest run that are regressions
            ActiveRegressions = regressions
                .Where(r => latestRun.Findings.Any(f => f.Title == r.Title))
                .ToList()
        };
    }

    private static int SeverityRank(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => 4,
        "WARNING" => 3,
        "INFO" => 2,
        "PASS" => 1,
        _ => 0
    };

    /// <summary>
    /// Format the regression report as human-readable text.
    /// </summary>
    public static string FormatText(RegressionReport report)
    {
        if (!report.HasData)
            return $"\n  {report.Message}\n";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════╗");
        sb.AppendLine("  ║     🔄 Regression Detection Report          ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Period:        {report.FirstRunDate.LocalDateTime:d} → {report.LastRunDate.LocalDateTime:d} ({report.AnalyzedDays} days)");
        sb.AppendLine($"  Runs analyzed: {report.AnalyzedRuns}");
        sb.AppendLine();

        if (report.TotalRegressions == 0)
        {
            sb.AppendLine("  ✅ No regressions detected! All resolved findings have stayed resolved.");
            sb.AppendLine();
            return sb.ToString();
        }

        sb.AppendLine($"  Total regressions:    {report.TotalRegressions}");
        if (report.CriticalRegressions > 0)
            sb.AppendLine($"  Critical regressions: {report.CriticalRegressions}");
        if (report.WarningRegressions > 0)
            sb.AppendLine($"  Warning regressions:  {report.WarningRegressions}");
        if (report.RepeatOffenders.Count > 0)
            sb.AppendLine($"  Repeat offenders:     {report.RepeatOffenders.Count} (regressed 2+ times)");
        if (report.ActiveRegressions.Count > 0)
            sb.AppendLine($"  Currently active:     {report.ActiveRegressions.Count}");
        sb.AppendLine();

        // Active regressions (currently present)
        if (report.ActiveRegressions.Count > 0)
        {
            sb.AppendLine("  ACTIVE REGRESSIONS (currently present)");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var r in report.ActiveRegressions)
            {
                var icon = r.Severity.ToUpperInvariant() == "CRITICAL" ? "🔴" : "🟡";
                sb.AppendLine($"  {icon} [{r.Severity}] {r.Title}");
                sb.AppendLine($"     Module: {r.ModuleName} | Regressed {r.RegressionCount}x");
                sb.AppendLine($"     First resolved: {r.FirstResolvedAt.LocalDateTime:g} | Last regressed: {r.LastRegressedAt.LocalDateTime:g}");
                if (!string.IsNullOrEmpty(r.Remediation))
                    sb.AppendLine($"     Fix: {r.Remediation}");
                sb.AppendLine();
            }
        }

        // Repeat offenders
        if (report.RepeatOffenders.Count > 0)
        {
            sb.AppendLine("  REPEAT OFFENDERS (regressed 2+ times)");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var r in report.RepeatOffenders)
            {
                sb.AppendLine($"  ⚠️  {r.Title} — regressed {r.RegressionCount} times");
                sb.AppendLine($"     Module: {r.ModuleName} | Severity: {r.Severity}");
                sb.AppendLine();
            }
        }

        // All regressions table
        sb.AppendLine("  ALL REGRESSIONS");
        sb.AppendLine("  ──────────────────────────────────────────");
        for (int i = 0; i < report.Regressions.Count; i++)
        {
            var r = report.Regressions[i];
            sb.AppendLine($"  {i + 1,3}. [{r.Severity}] {r.Title}");
            sb.AppendLine($"       Module: {r.ModuleName} | Count: {r.RegressionCount}x | Last: {r.LastRegressedAt.LocalDateTime:g}");
        }
        sb.AppendLine();

        return sb.ToString();
    }

    /// <summary>
    /// Serialize the report to a dictionary for JSON output.
    /// </summary>
    public static Dictionary<string, object?> ToDict(RegressionReport report) => new()
    {
        ["hasData"] = report.HasData,
        ["analyzedRuns"] = report.AnalyzedRuns,
        ["analyzedDays"] = report.AnalyzedDays,
        ["firstRunDate"] = report.FirstRunDate,
        ["lastRunDate"] = report.LastRunDate,
        ["totalRegressions"] = report.TotalRegressions,
        ["criticalRegressions"] = report.CriticalRegressions,
        ["warningRegressions"] = report.WarningRegressions,
        ["repeatOffenderCount"] = report.RepeatOffenders.Count,
        ["activeRegressionCount"] = report.ActiveRegressions.Count,
        ["regressions"] = report.Regressions.Select(r => new Dictionary<string, object?>
        {
            ["title"] = r.Title,
            ["severity"] = r.Severity,
            ["moduleName"] = r.ModuleName,
            ["description"] = r.Description,
            ["remediation"] = r.Remediation,
            ["firstResolvedAt"] = r.FirstResolvedAt,
            ["lastRegressedAt"] = r.LastRegressedAt,
            ["regressionCount"] = r.RegressionCount
        }).ToList()
    };
}

/// <summary>
/// Result of regression analysis.
/// </summary>
public class RegressionReport
{
    public bool HasData { get; set; }
    public string? Message { get; set; }
    public int AnalyzedRuns { get; set; }
    public int AnalyzedDays { get; set; }
    public DateTimeOffset FirstRunDate { get; set; }
    public DateTimeOffset LastRunDate { get; set; }
    public List<RegressionFinding> Regressions { get; set; } = [];
    public int TotalRegressions { get; set; }
    public int CriticalRegressions { get; set; }
    public int WarningRegressions { get; set; }
    public List<RegressionFinding> RepeatOffenders { get; set; } = [];
    public List<RegressionFinding> ActiveRegressions { get; set; } = [];
}

/// <summary>
/// A finding that regressed (was resolved, then reappeared).
/// </summary>
public class RegressionFinding
{
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string ModuleName { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Remediation { get; set; }
    public DateTimeOffset FirstResolvedAt { get; set; }
    public DateTimeOffset LastRegressedAt { get; set; }
    public int RegressionCount { get; set; }
}

internal class ResolvedInfo
{
    public DateTimeOffset ResolvedAt { get; set; }
    public string Severity { get; set; } = "";
    public string ModuleName { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Remediation { get; set; }
}
