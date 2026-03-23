using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Detects configuration drift by comparing a current audit against baselines.
/// Unlike baseline --check (which just shows regressions/resolved), drift detection
/// categorizes changes, calculates a drift score, and identifies oscillating findings
/// that keep appearing and disappearing between scans.
/// </summary>
public class DriftDetectionService
{
    private readonly BaselineService _baselineService;
    private readonly AuditHistoryService _historyService;

    public DriftDetectionService(BaselineService baselineService, AuditHistoryService historyService)
    {
        _baselineService = baselineService;
        _historyService = historyService;
    }

    /// <summary>
    /// Analyze configuration drift between the current report and a baseline.
    /// If no baseline name is provided, uses the most recent one.
    /// </summary>
    public DriftReport Analyze(SecurityReport currentReport, string? baselineName = null, int historyDays = 90)
    {
        // Find the baseline to compare against
        SecurityBaseline baseline;
        if (!string.IsNullOrEmpty(baselineName))
        {
            baseline = _baselineService.LoadBaseline(baselineName)
                ?? throw new InvalidOperationException($"Baseline '{baselineName}' not found.");
        }
        else
        {
            var baselines = _baselineService.ListBaselines();
            if (baselines.Count == 0)
                throw new InvalidOperationException(
                    "No baselines found. Create one first with: winsentinel --baseline save <name>");

            // Pick most recent
            var mostRecent = baselines.OrderByDescending(b => b.CreatedAt).First();
            baseline = _baselineService.LoadBaseline(mostRecent.Name)
                ?? throw new InvalidOperationException($"Could not load baseline '{mostRecent.Name}'.");
        }

        var report = new DriftReport
        {
            BaselineName = baseline.Name,
            BaselineCreatedAt = baseline.CreatedAt,
            BaselineScore = baseline.OverallScore,
            CurrentScore = currentReport.SecurityScore,
            AnalyzedAt = DateTimeOffset.Now,
        };

        // Build finding sets
        var baselineFindings = baseline.Findings.ToDictionary(f => f.Title, f => f, StringComparer.OrdinalIgnoreCase);
        var currentFindings = new Dictionary<string, (string Module, Finding Finding)>(StringComparer.OrdinalIgnoreCase);
        foreach (var result in currentReport.Results)
            foreach (var finding in result.Findings)
                currentFindings.TryAdd(finding.Title, (result.ModuleName, finding));

        // Categorize drift
        foreach (var (title, cf) in currentFindings)
        {
            if (!baselineFindings.ContainsKey(title))
            {
                report.DriftItems.Add(new DriftItem
                {
                    Title = title,
                    Module = cf.Module,
                    Severity = cf.Finding.Severity.ToString(),
                    Category = DriftCategory.NewFinding,
                    Description = cf.Finding.Description,
                    Remediation = cf.Finding.Remediation,
                });
            }
        }

        foreach (var (title, bf) in baselineFindings)
        {
            if (!currentFindings.ContainsKey(title))
            {
                report.DriftItems.Add(new DriftItem
                {
                    Title = title,
                    Module = bf.ModuleName,
                    Severity = bf.Severity,
                    Category = DriftCategory.Resolved,
                    Description = bf.Description,
                });
            }
            else
            {
                // Check severity change
                var current = currentFindings[title];
                if (!string.Equals(bf.Severity, current.Finding.Severity.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    report.DriftItems.Add(new DriftItem
                    {
                        Title = title,
                        Module = current.Module,
                        Severity = current.Finding.Severity.ToString(),
                        PreviousSeverity = bf.Severity,
                        Category = DriftCategory.SeverityChanged,
                        Description = current.Finding.Description,
                    });
                }
            }
        }

        // Module-level drift
        var baselineModules = baseline.ModuleScores.ToDictionary(m => m.ModuleName, m => m, StringComparer.OrdinalIgnoreCase);
        foreach (var result in currentReport.Results)
        {
            var currentModScore = SecurityScorer.CalculateCategoryScore(result);
            var baselineModScore = baselineModules.TryGetValue(result.ModuleName, out var bm) ? bm.Score : -1;

            if (baselineModScore >= 0 && baselineModScore != currentModScore)
            {
                report.ModuleDrifts.Add(new ModuleDrift
                {
                    Module = result.ModuleName,
                    Category = result.Category,
                    BaselineScore = baselineModScore,
                    CurrentScore = currentModScore,
                });
            }
        }

        // Detect oscillating findings from history
        DetectOscillations(report, historyDays);

        // Calculate drift score (0 = identical to baseline, 100 = completely different)
        CalculateDriftScore(report, baseline);

        // Classify overall drift level
        report.DriftLevel = report.DriftScore switch
        {
            0 => "Stable",
            <= 10 => "Minimal",
            <= 25 => "Moderate",
            <= 50 => "Significant",
            _ => "Critical"
        };

        return report;
    }

    private void DetectOscillations(DriftReport report, int historyDays)
    {
        try
        {
            _historyService.EnsureDatabase();
            var runs = _historyService.GetHistory(historyDays);
            if (runs.Count < 3) return;

            // Load findings for each run
            var runFindings = new List<HashSet<string>>();
            foreach (var run in runs.Take(10)) // Last 10 runs max
            {
                var details = _historyService.GetRunDetails(run.Id);
                if (details?.Findings != null)
                    runFindings.Add(new HashSet<string>(details.Findings.Select(f => f.Title), StringComparer.OrdinalIgnoreCase));
            }

            if (runFindings.Count < 3) return;

            // Find titles that flip between present/absent
            var allTitles = runFindings.SelectMany(s => s).Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var title in allTitles)
            {
                int flips = 0;
                for (int i = 1; i < runFindings.Count; i++)
                {
                    var wasPresentBefore = runFindings[i - 1].Contains(title);
                    var isPresentNow = runFindings[i].Contains(title);
                    if (wasPresentBefore != isPresentNow) flips++;
                }

                if (flips >= 2)
                {
                    report.OscillatingFindings.Add(new OscillatingFinding
                    {
                        Title = title,
                        FlipCount = flips,
                        RunsAnalyzed = runFindings.Count,
                    });
                }
            }

            report.OscillatingFindings = report.OscillatingFindings
                .OrderByDescending(f => f.FlipCount)
                .ToList();
        }
        catch
        {
            // History unavailable — skip oscillation detection
        }
    }

    private static void CalculateDriftScore(DriftReport report, SecurityBaseline baseline)
    {
        if (baseline.TotalFindings == 0 && report.DriftItems.Count == 0)
        {
            report.DriftScore = 0;
            return;
        }

        // Weighted scoring:
        // - New critical finding: 10 pts
        // - New warning: 5 pts
        // - Resolved finding: 2 pts (drift happened, even if positive)
        // - Severity change: 3 pts
        // - Oscillating: 4 pts each
        double rawScore = 0;

        foreach (var item in report.DriftItems)
        {
            rawScore += item.Category switch
            {
                DriftCategory.NewFinding when item.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) => 10,
                DriftCategory.NewFinding when item.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase) => 5,
                DriftCategory.NewFinding => 2,
                DriftCategory.Resolved => 2,
                DriftCategory.SeverityChanged => 3,
                _ => 1
            };
        }

        rawScore += report.OscillatingFindings.Count * 4;

        // Normalize: cap at 100, scale based on baseline size
        var maxExpected = Math.Max(baseline.TotalFindings * 2, 20);
        report.DriftScore = (int)Math.Min(100, rawScore / maxExpected * 100);
    }

    /// <summary>
    /// Render drift report as formatted text for console output.
    /// </summary>
    public static string RenderText(DriftReport report)
    {
        var sb = new StringBuilder();

        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════╗");
        sb.AppendLine("  ║       🔄 Configuration Drift Report         ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════╝");
        sb.AppendLine();

        sb.AppendLine($"  Baseline:     {report.BaselineName} (created {report.BaselineCreatedAt.LocalDateTime:g})");
        sb.AppendLine($"  Score:        {report.BaselineScore} → {report.CurrentScore} ({FormatDelta(report.CurrentScore - report.BaselineScore)})");
        sb.AppendLine($"  Drift Score:  {report.DriftScore}/100 — {report.DriftLevel}");

        var elapsed = report.AnalyzedAt - report.BaselineCreatedAt;
        sb.AppendLine($"  Time elapsed: {FormatElapsed(elapsed)}");
        sb.AppendLine();

        // New findings (regressions)
        var newFindings = report.DriftItems.Where(d => d.Category == DriftCategory.NewFinding).ToList();
        if (newFindings.Count > 0)
        {
            sb.AppendLine($"  ⚠ NEW FINDINGS ({newFindings.Count})");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var item in newFindings.OrderByDescending(i => SeverityRank(i.Severity)))
            {
                sb.AppendLine($"    [{item.Severity}] {item.Title}");
                sb.AppendLine($"           Module: {item.Module}");
                if (!string.IsNullOrEmpty(item.Remediation))
                    sb.AppendLine($"           Fix: {item.Remediation}");
            }
            sb.AppendLine();
        }

        // Severity changes
        var sevChanges = report.DriftItems.Where(d => d.Category == DriftCategory.SeverityChanged).ToList();
        if (sevChanges.Count > 0)
        {
            sb.AppendLine($"  ~ SEVERITY CHANGES ({sevChanges.Count})");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var item in sevChanges)
                sb.AppendLine($"    {item.Title}: {item.PreviousSeverity} → {item.Severity}");
            sb.AppendLine();
        }

        // Resolved
        var resolved = report.DriftItems.Where(d => d.Category == DriftCategory.Resolved).ToList();
        if (resolved.Count > 0)
        {
            sb.AppendLine($"  ✓ RESOLVED ({resolved.Count})");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var item in resolved)
                sb.AppendLine($"    [{item.Severity}] {item.Title}");
            sb.AppendLine();
        }

        // Oscillating findings
        if (report.OscillatingFindings.Count > 0)
        {
            sb.AppendLine($"  🔁 OSCILLATING FINDINGS ({report.OscillatingFindings.Count})");
            sb.AppendLine("  ──────────────────────────────────────────");
            sb.AppendLine("  These findings keep appearing and disappearing between scans:");
            foreach (var osc in report.OscillatingFindings.Take(10))
                sb.AppendLine($"    {osc.Title} — flipped {osc.FlipCount}x in {osc.RunsAnalyzed} runs");
            sb.AppendLine();
        }

        // Module drift
        if (report.ModuleDrifts.Count > 0)
        {
            sb.AppendLine("  MODULE DRIFT");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var md in report.ModuleDrifts.OrderBy(m => m.CurrentScore - m.BaselineScore))
            {
                var delta = md.CurrentScore - md.BaselineScore;
                var arrow = delta > 0 ? "↑" : "↓";
                sb.AppendLine($"    {md.Category,-25} {md.BaselineScore,3} → {md.CurrentScore,3} ({arrow}{Math.Abs(delta)})");
            }
            sb.AppendLine();
        }

        if (report.DriftItems.Count == 0 && report.OscillatingFindings.Count == 0)
        {
            sb.AppendLine("  ✓ No configuration drift detected. System matches baseline.");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    public static string RenderJson(DriftReport report)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(report, jsonOptions);
    }

    private static string FormatDelta(int delta) =>
        delta switch
        {
            > 0 => $"+{delta}",
            0 => "no change",
            _ => delta.ToString()
        };

    private static string FormatElapsed(TimeSpan ts) =>
        ts.TotalDays switch
        {
            < 1 => $"{(int)ts.TotalHours}h",
            < 7 => $"{(int)ts.TotalDays}d",
            < 30 => $"{(int)(ts.TotalDays / 7)}w {(int)(ts.TotalDays % 7)}d",
            _ => $"{(int)(ts.TotalDays / 30)}mo"
        };

    private static int SeverityRank(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" => 3,
            "warning" => 2,
            "info" => 1,
            _ => 0
        };
}

// ── Models ───────────────────────────────────────────────────────────

public class DriftReport
{
    public string BaselineName { get; set; } = "";
    public DateTimeOffset BaselineCreatedAt { get; set; }
    public int BaselineScore { get; set; }
    public int CurrentScore { get; set; }
    public int DriftScore { get; set; }
    public string DriftLevel { get; set; } = "Unknown";
    public DateTimeOffset AnalyzedAt { get; set; }
    public List<DriftItem> DriftItems { get; set; } = [];
    public List<ModuleDrift> ModuleDrifts { get; set; } = [];
    public List<OscillatingFinding> OscillatingFindings { get; set; } = [];
}

public class DriftItem
{
    public string Title { get; set; } = "";
    public string Module { get; set; } = "";
    public string Severity { get; set; } = "";
    public string? PreviousSeverity { get; set; }
    public DriftCategory Category { get; set; }
    public string? Description { get; set; }
    public string? Remediation { get; set; }
}

public class ModuleDrift
{
    public string Module { get; set; } = "";
    public string Category { get; set; } = "";
    public int BaselineScore { get; set; }
    public int CurrentScore { get; set; }
    public int Delta => CurrentScore - BaselineScore;
}

public class OscillatingFinding
{
    public string Title { get; set; } = "";
    public int FlipCount { get; set; }
    public int RunsAnalyzed { get; set; }
}

public enum DriftCategory
{
    NewFinding,
    Resolved,
    SeverityChanged
}
