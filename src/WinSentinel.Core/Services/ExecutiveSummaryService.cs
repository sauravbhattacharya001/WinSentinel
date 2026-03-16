using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a one-page executive summary combining score, grade, module health,
/// top risks, trend context, and prioritized action items.
/// </summary>
public class ExecutiveSummaryService
{
    /// <summary>
    /// Executive summary output model.
    /// </summary>
    public record ExecutiveSummary
    {
        // ── Headline ──
        public int Score { get; init; }
        public string Grade { get; init; } = "";
        public string Verdict { get; init; } = "";
        public DateTimeOffset GeneratedAt { get; init; }
        public string MachineName { get; init; } = "";

        // ── Counts ──
        public int TotalFindings { get; init; }
        public int CriticalCount { get; init; }
        public int WarningCount { get; init; }
        public int InfoCount { get; init; }
        public int PassCount { get; init; }
        public int ModulesScanned { get; init; }

        // ── Module Health ──
        public List<ModuleHealth> Modules { get; init; } = new();

        // ── Top Risks ──
        public List<RiskItem> TopRisks { get; init; } = new();

        // ── Strengths ──
        public List<string> Strengths { get; init; } = new();

        // ── Action Items ──
        public List<ActionItem> ActionItems { get; init; } = new();

        // ── Trend (optional, null if no history) ──
        public TrendSnapshot? Trend { get; init; }
    }

    public record ModuleHealth
    {
        public string Category { get; init; } = "";
        public int Score { get; init; }
        public string Grade { get; init; } = "";
        public int Critical { get; init; }
        public int Warnings { get; init; }
        public string Status { get; init; } = ""; // "healthy", "at-risk", "critical"
    }

    public record RiskItem
    {
        public int Rank { get; init; }
        public string Title { get; init; } = "";
        public string Severity { get; init; } = "";
        public string Module { get; init; } = "";
        public string? Remediation { get; init; }
        public bool HasAutoFix { get; init; }
    }

    public record ActionItem
    {
        public int Priority { get; init; }
        public string Action { get; init; } = "";
        public string Impact { get; init; } = ""; // "high", "medium", "low"
        public string Effort { get; init; } = ""; // "quick", "moderate", "significant"
    }

    public record TrendSnapshot
    {
        public int? PreviousScore { get; init; }
        public int ScoreChange { get; init; }
        public string Direction { get; init; } = ""; // "improving", "declining", "stable"
        public int TotalScans { get; init; }
        public double AverageScore { get; init; }
    }

    /// <summary>
    /// Generate an executive summary from an audit report.
    /// Optionally include trend data from history.
    /// </summary>
    public ExecutiveSummary Generate(SecurityReport report, ScoreTrendSummary? trend = null)
    {
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var verdict = GetVerdict(report.SecurityScore, report.TotalCritical);

        // Module health
        var modules = report.Results
            .OrderBy(r => r.Score)
            .Select(r => new ModuleHealth
            {
                Category = r.Category,
                Score = r.Score,
                Grade = SecurityScorer.GetGrade(r.Score),
                Critical = r.CriticalCount,
                Warnings = r.WarningCount,
                Status = r.CriticalCount > 0 ? "critical" : r.WarningCount > 0 ? "at-risk" : "healthy"
            })
            .ToList();

        // Top risks — critical first, then warnings, limited to 5
        var topRisks = report.Results
            .SelectMany(r => r.Findings.Select(f => new { Finding = f, Module = r.Category }))
            .Where(x => x.Finding.Severity is Severity.Critical or Severity.Warning)
            .OrderByDescending(x => x.Finding.Severity)
            .ThenBy(x => x.Finding.Title)
            .Take(5)
            .Select((x, i) => new RiskItem
            {
                Rank = i + 1,
                Title = x.Finding.Title,
                Severity = x.Finding.Severity.ToString(),
                Module = x.Module,
                Remediation = x.Finding.Remediation,
                HasAutoFix = !string.IsNullOrWhiteSpace(x.Finding.FixCommand)
            })
            .ToList();

        // Strengths — modules with 100% score
        var strengths = modules
            .Where(m => m.Score == 100)
            .Select(m => m.Category)
            .ToList();

        // Action items — synthesized recommendations
        var actions = GenerateActionItems(report, modules);

        // Trend snapshot
        TrendSnapshot? trendSnapshot = null;
        if (trend != null && trend.TotalScans >= 2)
        {
            var change = trend.ScoreChange;
            var direction = change > 2 ? "improving" : change < -2 ? "declining" : "stable";
            trendSnapshot = new TrendSnapshot
            {
                PreviousScore = trend.PreviousScore,
                ScoreChange = change,
                Direction = direction,
                TotalScans = trend.TotalScans,
                AverageScore = Math.Round(trend.AverageScore, 1)
            };
        }

        return new ExecutiveSummary
        {
            Score = report.SecurityScore,
            Grade = grade,
            Verdict = verdict,
            GeneratedAt = report.GeneratedAt,
            MachineName = Environment.MachineName,
            TotalFindings = report.TotalFindings,
            CriticalCount = report.TotalCritical,
            WarningCount = report.TotalWarnings,
            InfoCount = report.TotalInfo,
            PassCount = report.TotalPass,
            ModulesScanned = report.Results.Count,
            Modules = modules,
            TopRisks = topRisks,
            Strengths = strengths,
            ActionItems = actions,
            Trend = trendSnapshot
        };
    }

    private static string GetVerdict(int score, int criticalCount)
    {
        if (criticalCount > 5)
            return "Immediate attention required — multiple critical vulnerabilities detected.";
        if (criticalCount > 0)
            return "Critical issues found that should be addressed promptly.";
        if (score >= 90)
            return "System security posture is strong. Minor improvements possible.";
        if (score >= 75)
            return "Generally secure with some areas needing attention.";
        if (score >= 60)
            return "Moderate risk — several security gaps should be addressed.";
        return "High risk — significant security improvements needed.";
    }

    private static List<ActionItem> GenerateActionItems(SecurityReport report, List<ModuleHealth> modules)
    {
        var actions = new List<ActionItem>();
        int priority = 1;

        // Critical modules first
        var criticalModules = modules.Where(m => m.Status == "critical").ToList();
        if (criticalModules.Count > 0)
        {
            actions.Add(new ActionItem
            {
                Priority = priority++,
                Action = $"Fix critical findings in: {string.Join(", ", criticalModules.Select(m => m.Category))}",
                Impact = "high",
                Effort = "moderate"
            });
        }

        // Auto-fixable items
        var autoFixCount = report.Results
            .SelectMany(r => r.Findings)
            .Count(f => f.Severity is Severity.Critical or Severity.Warning && !string.IsNullOrWhiteSpace(f.FixCommand));
        if (autoFixCount > 0)
        {
            actions.Add(new ActionItem
            {
                Priority = priority++,
                Action = $"Run --harden to auto-fix {autoFixCount} finding(s) with available remediation scripts",
                Impact = "high",
                Effort = "quick"
            });
        }

        // At-risk modules
        var atRiskModules = modules.Where(m => m.Status == "at-risk" && m.Score < 70).ToList();
        if (atRiskModules.Count > 0)
        {
            actions.Add(new ActionItem
            {
                Priority = priority++,
                Action = $"Review warnings in: {string.Join(", ", atRiskModules.Select(m => m.Category))}",
                Impact = "medium",
                Effort = "moderate"
            });
        }

        // Low-scoring modules
        var lowModules = modules.Where(m => m.Score < 50 && m.Status != "critical").ToList();
        if (lowModules.Count > 0)
        {
            actions.Add(new ActionItem
            {
                Priority = priority++,
                Action = $"Investigate low-scoring modules: {string.Join(", ", lowModules.Select(m => $"{m.Category} ({m.Score}%)"))}",
                Impact = "medium",
                Effort = "significant"
            });
        }

        // Baseline suggestion if score is decent
        if (report.SecurityScore >= 70 && actions.Count < 3)
        {
            actions.Add(new ActionItem
            {
                Priority = priority++,
                Action = "Save a baseline with --baseline save <name> to track future regressions",
                Impact = "low",
                Effort = "quick"
            });
        }

        // Schedule suggestion
        if (actions.Count < 5)
        {
            actions.Add(new ActionItem
            {
                Priority = priority,
                Action = "Set up scheduled audits to catch regressions early",
                Impact = "medium",
                Effort = "quick"
            });
        }

        return actions;
    }

    /// <summary>
    /// Render a plain-text executive summary for console output.
    /// </summary>
    public static string RenderText(ExecutiveSummary summary)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine();
        sb.AppendLine("  ══════════════════════════════════════════════════");
        sb.AppendLine("            EXECUTIVE SECURITY SUMMARY             ");
        sb.AppendLine("  ══════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"  Machine:  {summary.MachineName}");
        sb.AppendLine($"  Date:     {summary.GeneratedAt.LocalDateTime:f}");
        sb.AppendLine();

        // Score headline
        sb.AppendLine($"  SECURITY SCORE: {summary.Score}/100  ({summary.Grade})");
        sb.AppendLine($"  {summary.Verdict}");
        sb.AppendLine();

        // Finding counts
        sb.AppendLine($"  Findings: {summary.TotalFindings} total");
        sb.AppendLine($"    Critical: {summary.CriticalCount}  |  Warnings: {summary.WarningCount}  |  Info: {summary.InfoCount}  |  Pass: {summary.PassCount}");
        sb.AppendLine($"    Modules scanned: {summary.ModulesScanned}");
        sb.AppendLine();

        // Trend
        if (summary.Trend != null)
        {
            var arrow = summary.Trend.Direction switch
            {
                "improving" => "↑",
                "declining" => "↓",
                _ => "→"
            };
            var sign = summary.Trend.ScoreChange >= 0 ? "+" : "";
            sb.AppendLine($"  TREND: {arrow} {sign}{summary.Trend.ScoreChange} pts ({summary.Trend.Direction})");
            sb.AppendLine($"    Previous: {summary.Trend.PreviousScore}  |  Average: {summary.Trend.AverageScore}  |  Scans: {summary.Trend.TotalScans}");
            sb.AppendLine();
        }

        // Module health table
        sb.AppendLine("  MODULE HEALTH");
        sb.AppendLine("  ──────────────────────────────────────────");
        sb.AppendLine($"  {"Module",-22} {"Score",5}  {"Grade",5}  Status");
        sb.AppendLine($"  {"──────────────────────",-22} {"─────",5}  {"─────",5}  ──────────");
        foreach (var m in summary.Modules)
        {
            var statusIcon = m.Status switch
            {
                "critical" => "🔴 critical",
                "at-risk" => "🟡 at-risk",
                _ => "🟢 healthy"
            };
            sb.AppendLine($"  {m.Category,-22} {m.Score,5}  {m.Grade,5}  {statusIcon}");
        }
        sb.AppendLine();

        // Top risks
        if (summary.TopRisks.Count > 0)
        {
            sb.AppendLine("  TOP RISKS");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var risk in summary.TopRisks)
            {
                var fixTag = risk.HasAutoFix ? " [auto-fixable]" : "";
                sb.AppendLine($"  {risk.Rank}. [{risk.Severity}] {risk.Title}{fixTag}");
                sb.AppendLine($"     Module: {risk.Module}");
                if (risk.Remediation != null)
                    sb.AppendLine($"     Fix: {risk.Remediation}");
            }
            sb.AppendLine();
        }

        // Strengths
        if (summary.Strengths.Count > 0)
        {
            sb.AppendLine($"  STRENGTHS: {string.Join(", ", summary.Strengths)}");
            sb.AppendLine();
        }

        // Action items
        if (summary.ActionItems.Count > 0)
        {
            sb.AppendLine("  ACTION ITEMS");
            sb.AppendLine("  ──────────────────────────────────────────");
            foreach (var item in summary.ActionItems)
            {
                var impactTag = item.Impact == "high" ? "‼️" : item.Impact == "medium" ? "❗" : "ℹ️";
                sb.AppendLine($"  {item.Priority}. {impactTag} {item.Action}");
                sb.AppendLine($"     Impact: {item.Impact}  |  Effort: {item.Effort}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("  ══════════════════════════════════════════════════");

        return sb.ToString();
    }

    /// <summary>
    /// Render a self-contained HTML executive summary.
    /// </summary>
    public static string RenderHtml(ExecutiveSummary summary)
    {
        var scoreColor = summary.Score >= 80 ? "#22c55e" : summary.Score >= 60 ? "#eab308" : "#ef4444";
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.AppendLine($"<title>Executive Summary — {summary.MachineName}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("*{margin:0;padding:0;box-sizing:border-box}");
        sb.AppendLine("body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}");
        sb.AppendLine(".card{background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}");
        sb.AppendLine("h1{text-align:center;font-size:1.5rem;margin-bottom:1rem;color:#94a3b8}");
        sb.AppendLine(".score{text-align:center;font-size:4rem;font-weight:700;margin:.5rem 0}");
        sb.AppendLine(".grade{text-align:center;font-size:1.5rem;opacity:.8}");
        sb.AppendLine(".verdict{text-align:center;font-style:italic;color:#94a3b8;margin:.5rem 0}");
        sb.AppendLine(".counts{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin:1rem 0}");
        sb.AppendLine(".count-box{padding:.5rem 1rem;border-radius:8px;text-align:center;min-width:80px}");
        sb.AppendLine(".crit{background:#7f1d1d;color:#fca5a5}.warn{background:#713f12;color:#fde68a}");
        sb.AppendLine(".info-box{background:#1e3a5f;color:#93c5fd}.pass-box{background:#14532d;color:#86efac}");
        sb.AppendLine("h2{font-size:1.1rem;color:#94a3b8;margin-bottom:.75rem;border-bottom:1px solid #334155;padding-bottom:.5rem}");
        sb.AppendLine("table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.4rem .6rem}");
        sb.AppendLine("th{color:#64748b;font-size:.8rem;text-transform:uppercase}");
        sb.AppendLine("tr:nth-child(even){background:#0f172a33}");
        sb.AppendLine(".risk{padding:.4rem 0;border-bottom:1px solid #334155}");
        sb.AppendLine(".risk-title{font-weight:600}.risk-meta{font-size:.85rem;color:#94a3b8}");
        sb.AppendLine(".action{padding:.5rem 0;border-bottom:1px solid #334155}");
        sb.AppendLine(".action-text{font-weight:500}.action-meta{font-size:.8rem;color:#64748b}");
        sb.AppendLine(".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}");
        sb.AppendLine(".badge-crit{background:#7f1d1d;color:#fca5a5}.badge-warn{background:#713f12;color:#fde68a}");
        sb.AppendLine(".badge-fix{background:#14532d;color:#86efac}");
        sb.AppendLine(".healthy{color:#22c55e}.at-risk{color:#eab308}.critical-status{color:#ef4444}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>🛡️ Executive Security Summary</h1>");

        // Score card
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine($"<div class=\"score\" style=\"color:{scoreColor}\">{summary.Score}/100</div>");
        sb.AppendLine($"<div class=\"grade\">Grade: {summary.Grade}</div>");
        sb.AppendLine($"<div class=\"verdict\">{summary.Verdict}</div>");
        sb.AppendLine($"<div style=\"text-align:center;color:#64748b;font-size:.85rem\">{summary.MachineName} — {summary.GeneratedAt.LocalDateTime:f}</div>");
        sb.AppendLine("<div class=\"counts\">");
        sb.AppendLine($"<div class=\"count-box crit\"><div style=\"font-size:1.5rem\">{summary.CriticalCount}</div><div>Critical</div></div>");
        sb.AppendLine($"<div class=\"count-box warn\"><div style=\"font-size:1.5rem\">{summary.WarningCount}</div><div>Warnings</div></div>");
        sb.AppendLine($"<div class=\"count-box info-box\"><div style=\"font-size:1.5rem\">{summary.InfoCount}</div><div>Info</div></div>");
        sb.AppendLine($"<div class=\"count-box pass-box\"><div style=\"font-size:1.5rem\">{summary.PassCount}</div><div>Pass</div></div>");
        sb.AppendLine("</div></div>");

        // Trend
        if (summary.Trend != null)
        {
            var arrow = summary.Trend.Direction switch { "improving" => "↑", "declining" => "↓", _ => "→" };
            var trendColor = summary.Trend.Direction switch { "improving" => "#22c55e", "declining" => "#ef4444", _ => "#94a3b8" };
            sb.AppendLine("<div class=\"card\">");
            sb.AppendLine("<h2>📈 Trend</h2>");
            sb.AppendLine($"<div style=\"font-size:1.2rem;color:{trendColor}\">{arrow} {(summary.Trend.ScoreChange >= 0 ? "+" : "")}{summary.Trend.ScoreChange} pts ({summary.Trend.Direction})</div>");
            sb.AppendLine($"<div style=\"color:#94a3b8;font-size:.85rem\">Previous: {summary.Trend.PreviousScore} | Average: {summary.Trend.AverageScore} | Scans: {summary.Trend.TotalScans}</div>");
            sb.AppendLine("</div>");
        }

        // Module health
        sb.AppendLine("<div class=\"card\"><h2>🔍 Module Health</h2><table>");
        sb.AppendLine("<tr><th>Module</th><th>Score</th><th>Grade</th><th>Status</th></tr>");
        foreach (var m in summary.Modules)
        {
            var cls = m.Status switch { "critical" => "critical-status", "at-risk" => "at-risk", _ => "healthy" };
            sb.AppendLine($"<tr><td>{m.Category}</td><td>{m.Score}</td><td>{m.Grade}</td><td class=\"{cls}\">{m.Status}</td></tr>");
        }
        sb.AppendLine("</table></div>");

        // Top risks
        if (summary.TopRisks.Count > 0)
        {
            sb.AppendLine("<div class=\"card\"><h2>⚠️ Top Risks</h2>");
            foreach (var r in summary.TopRisks)
            {
                var badge = r.Severity == "Critical" ? "badge-crit" : "badge-warn";
                var fixBadge = r.HasAutoFix ? " <span class=\"badge badge-fix\">auto-fixable</span>" : "";
                sb.AppendLine($"<div class=\"risk\"><div class=\"risk-title\">{r.Rank}. <span class=\"badge {badge}\">{r.Severity}</span> {System.Net.WebUtility.HtmlEncode(r.Title)}{fixBadge}</div>");
                sb.AppendLine($"<div class=\"risk-meta\">{r.Module}{(r.Remediation != null ? $" — {System.Net.WebUtility.HtmlEncode(r.Remediation)}" : "")}</div></div>");
            }
            sb.AppendLine("</div>");
        }

        // Action items
        if (summary.ActionItems.Count > 0)
        {
            sb.AppendLine("<div class=\"card\"><h2>📋 Action Items</h2>");
            foreach (var a in summary.ActionItems)
            {
                var icon = a.Impact == "high" ? "‼️" : a.Impact == "medium" ? "❗" : "ℹ️";
                sb.AppendLine($"<div class=\"action\"><div class=\"action-text\">{a.Priority}. {icon} {System.Net.WebUtility.HtmlEncode(a.Action)}</div>");
                sb.AppendLine($"<div class=\"action-meta\">Impact: {a.Impact} | Effort: {a.Effort}</div></div>");
            }
            sb.AppendLine("</div>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }
}
