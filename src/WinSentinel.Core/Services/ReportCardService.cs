using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a graded Security Posture Report Card from a current
/// <see cref="SecurityReport"/> and optional historical scan data.
/// <para>
/// Each audit module receives a letter grade (A–F) derived from its score.
/// Grades are converted to a 4.0-scale GPA. The report highlights
/// improvements, regressions, grade distribution, and prioritised next
/// steps to raise the overall GPA.
/// </para>
/// </summary>
public class ReportCardService
{
    /// <summary>
    /// Build a report card from a live audit report.
    /// </summary>
    /// <param name="report">Current audit report.</param>
    /// <param name="previousModuleScores">
    /// Module scores from the previous scan (optional).
    /// Used to compute trends, improvements, and regressions.
    /// </param>
    /// <param name="previousOverallScore">Previous overall score (optional).</param>
    public ReportCard Generate(
        SecurityReport report,
        List<ModuleScoreRecord>? previousModuleScores = null,
        int? previousOverallScore = null)
    {
        ArgumentNullException.ThrowIfNull(report);

        var prevLookup = previousModuleScores?
            .ToDictionary(m => m.ModuleName, m => m, StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, ModuleScoreRecord>(StringComparer.OrdinalIgnoreCase);

        var card = new ReportCard
        {
            OverallScore = report.SecurityScore,
            OverallGrade = SecurityScorer.GetGrade(report.SecurityScore),
        };

        // Build per-module grades
        foreach (var result in report.Results)
        {
            var score = result.Score;
            var grade = SecurityScorer.GetGrade(score);
            var gp = GradeToPoints(grade);

            var mg = new ModuleGrade
            {
                ModuleName = result.ModuleName,
                Category = result.Category,
                Score = score,
                Grade = grade,
                GradePoints = gp,
                CriticalCount = result.CriticalCount,
                WarningCount = result.WarningCount,
                InfoCount = result.InfoCount,
                PassCount = result.PassCount,
            };

            if (prevLookup.TryGetValue(result.ModuleName, out var prev))
            {
                mg.PreviousScore = prev.Score;
                mg.ScoreChange = score - prev.Score;
                mg.Trend = mg.ScoreChange > 0 ? "↑" : mg.ScoreChange < 0 ? "↓" : "→";
            }

            card.Modules.Add(mg);
        }

        // Sort worst-first
        card.Modules = card.Modules.OrderBy(m => m.Score).ToList();
        card.TotalModules = card.Modules.Count;

        // GPA
        card.Gpa = card.Modules.Count > 0
            ? Math.Round(card.Modules.Average(m => m.GradePoints), 2)
            : 4.0;

        if (previousOverallScore.HasValue)
        {
            var prevGpa = previousModuleScores is { Count: > 0 }
                ? Math.Round(previousModuleScores.Average(m => GradeToPoints(SecurityScorer.GetGrade(m.Score))), 2)
                : ScoreToGpa(previousOverallScore.Value);
            card.PreviousGpa = prevGpa;
            card.GpaTrend = card.Gpa > prevGpa ? "↑"
                          : card.Gpa < prevGpa ? "↓"
                          : "→";
        }

        // Grade distribution
        foreach (var g in new[] { "A", "B", "C", "D", "F" })
            card.GradeDistribution[g] = card.Modules.Count(m => m.Grade == g);

        // Improvements & regressions
        foreach (var m in card.Modules.Where(m => m.PreviousScore.HasValue))
        {
            if (m.ScoreChange > 0)
            {
                card.Improvements.Add(new ModuleChange
                {
                    ModuleName = m.ModuleName,
                    Category = m.Category,
                    PreviousScore = m.PreviousScore!.Value,
                    CurrentScore = m.Score,
                    ScoreChange = m.ScoreChange,
                    PreviousGrade = SecurityScorer.GetGrade(m.PreviousScore.Value),
                    CurrentGrade = m.Grade,
                });
            }
            else if (m.ScoreChange < 0)
            {
                card.Regressions.Add(new ModuleChange
                {
                    ModuleName = m.ModuleName,
                    Category = m.Category,
                    PreviousScore = m.PreviousScore!.Value,
                    CurrentScore = m.Score,
                    ScoreChange = m.ScoreChange,
                    PreviousGrade = SecurityScorer.GetGrade(m.PreviousScore.Value),
                    CurrentGrade = m.Grade,
                });
            }
        }

        card.Improvements = card.Improvements.OrderByDescending(c => c.ScoreChange).ToList();
        card.Regressions = card.Regressions.OrderBy(c => c.ScoreChange).ToList();

        // Next steps
        card.NextSteps = GenerateNextSteps(card);

        return card;
    }

    /// <summary>
    /// Build a report card from history records (for offline / history-based cards).
    /// </summary>
    public ReportCard GenerateFromHistory(
        AuditRunRecord currentRun,
        AuditRunRecord? previousRun = null)
    {
        ArgumentNullException.ThrowIfNull(currentRun);

        // Convert to a lightweight SecurityReport-compatible structure
        var report = new SecurityReport
        {
            SecurityScore = currentRun.OverallScore,
            GeneratedAt = currentRun.Timestamp,
        };

        // Build AuditResults from module scores
        foreach (var ms in currentRun.ModuleScores)
        {
            var result = new AuditResult
            {
                ModuleName = ms.ModuleName,
                Category = ms.Category,
            };
            // Populate dummy findings to produce the correct score
            for (int i = 0; i < ms.CriticalCount; i++)
                result.Findings.Add(new Finding { Title = $"crit-{i}", Category = ms.Category, Severity = Severity.Critical, Description = "" });
            for (int i = 0; i < ms.WarningCount; i++)
                result.Findings.Add(new Finding { Title = $"warn-{i}", Category = ms.Category, Severity = Severity.Warning, Description = "" });
            // Ensure score matches
            report.Results.Add(result);
        }

        report.SecurityScore = currentRun.OverallScore;

        return Generate(
            report,
            previousRun?.ModuleScores,
            previousRun?.OverallScore);
    }

    // ── Formatting ───────────────────────────────────────────────

    /// <summary>Render a plain-text report card.</summary>
    public static string FormatText(ReportCard card)
    {
        ArgumentNullException.ThrowIfNull(card);
        var sb = new System.Text.StringBuilder();

        sb.AppendLine();
        sb.AppendLine("  ╔══════════════════════════════════════════════════╗");
        sb.AppendLine("  ║       🎓  Security Posture Report Card          ║");
        sb.AppendLine("  ╚══════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Machine:  {card.MachineName}");
        sb.AppendLine($"  Date:     {card.GeneratedAt.LocalDateTime:g}");
        sb.AppendLine();

        // Overall
        sb.AppendLine($"  Overall Score:  {card.OverallScore}/100  ({card.OverallGrade})");
        sb.Append($"  GPA:            {card.Gpa:F2} / 4.00  {card.GpaTrend}");
        if (card.PreviousGpa.HasValue)
            sb.Append($"  (was {card.PreviousGpa.Value:F2})");
        sb.AppendLine();
        sb.AppendLine();

        // Grade distribution bar
        sb.AppendLine("  Grade Distribution");
        sb.AppendLine("  ──────────────────────────────────────────────");
        foreach (var g in new[] { "A", "B", "C", "D", "F" })
        {
            var count = card.GradeDistribution.GetValueOrDefault(g, 0);
            var bar = new string('█', count) + new string('░', Math.Max(0, card.TotalModules - count));
            sb.AppendLine($"    {g}: {bar} {count}");
        }
        sb.AppendLine();

        // Module grades table
        sb.AppendLine("  Module Grades");
        sb.AppendLine("  ──────────────────────────────────────────────");
        sb.AppendLine($"  {"Module",-24} {"Score",5} {"Grade",5} {"Trend",5} {"Crit",5} {"Warn",5}");
        sb.AppendLine($"  {"────────────────────────",-24} {"─────",5} {"─────",5} {"─────",5} {"─────",5} {"─────",5}");
        foreach (var m in card.Modules)
        {
            sb.AppendLine($"  {m.Category,-24} {m.Score,5} {m.Grade,5} {m.Trend,5} {m.CriticalCount,5} {m.WarningCount,5}");
        }
        sb.AppendLine();

        // Improvements
        if (card.Improvements.Count > 0)
        {
            sb.AppendLine("  ✅ Improvements");
            sb.AppendLine("  ──────────────────────────────────────────────");
            foreach (var imp in card.Improvements)
                sb.AppendLine($"    ↑ {imp.Category,-20} {imp.PreviousGrade} → {imp.CurrentGrade}  (+{imp.ScoreChange} pts)");
            sb.AppendLine();
        }

        // Regressions
        if (card.Regressions.Count > 0)
        {
            sb.AppendLine("  ⚠️  Regressions");
            sb.AppendLine("  ──────────────────────────────────────────────");
            foreach (var reg in card.Regressions)
                sb.AppendLine($"    ↓ {reg.Category,-20} {reg.PreviousGrade} → {reg.CurrentGrade}  ({reg.ScoreChange} pts)");
            sb.AppendLine();
        }

        // Next steps
        if (card.NextSteps.Count > 0)
        {
            sb.AppendLine("  📋 Next Steps");
            sb.AppendLine("  ──────────────────────────────────────────────");
            for (int i = 0; i < card.NextSteps.Count; i++)
                sb.AppendLine($"    {i + 1}. {card.NextSteps[i]}");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>Render an HTML report card.</summary>
    public static string FormatHtml(ReportCard card)
    {
        ArgumentNullException.ThrowIfNull(card);
        var sb = new System.Text.StringBuilder();

        var gpaColor = card.Gpa >= 3.0 ? "#4CAF50" : card.Gpa >= 2.0 ? "#FFC107" : "#F44336";

        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>Security Report Card</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;margin:40px auto;max-width:800px}");
        sb.AppendLine("h1{text-align:center;color:#fff}h2{color:#8ab4f8;border-bottom:1px solid #333;padding-bottom:8px}");
        sb.AppendLine("table{width:100%;border-collapse:collapse;margin:16px 0}");
        sb.AppendLine("th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #333}");
        sb.AppendLine("th{color:#8ab4f8;font-weight:600}");
        sb.AppendLine(".grade-A{color:#4CAF50;font-weight:bold}.grade-B{color:#8BC34A;font-weight:bold}");
        sb.AppendLine(".grade-C{color:#FFC107;font-weight:bold}.grade-D{color:#FF9800;font-weight:bold}");
        sb.AppendLine(".grade-F{color:#F44336;font-weight:bold}");
        sb.AppendLine(".gpa{font-size:2.5em;text-align:center;margin:16px 0}");
        sb.AppendLine(".card{background:#16213e;border-radius:12px;padding:20px;margin:16px 0}");
        sb.AppendLine(".imp{color:#4CAF50}.reg{color:#F44336}");
        sb.AppendLine("ol{padding-left:20px}li{margin:4px 0}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>🎓 Security Posture Report Card</h1>");
        sb.AppendLine($"<p style='text-align:center;color:#888'>{card.MachineName} — {card.GeneratedAt.LocalDateTime:g}</p>");

        // GPA hero
        sb.AppendLine("<div class='card' style='text-align:center'>");
        sb.AppendLine($"<div class='gpa' style='color:{gpaColor}'>{card.Gpa:F2} <span style='font-size:0.5em'>/ 4.00 {card.GpaTrend}</span></div>");
        sb.AppendLine($"<p>Overall Score: {card.OverallScore}/100 (<span class='grade-{card.OverallGrade}'>{card.OverallGrade}</span>)</p>");
        if (card.PreviousGpa.HasValue)
            sb.AppendLine($"<p style='color:#888'>Previous GPA: {card.PreviousGpa.Value:F2}</p>");
        sb.AppendLine("</div>");

        // Module table
        sb.AppendLine("<h2>Module Grades</h2><table><tr><th>Module</th><th>Score</th><th>Grade</th><th>Trend</th><th>Critical</th><th>Warnings</th></tr>");
        foreach (var m in card.Modules)
        {
            sb.AppendLine($"<tr><td>{Esc(m.Category)}</td><td>{m.Score}</td><td class='grade-{m.Grade}'>{m.Grade}</td><td>{m.Trend}</td><td>{m.CriticalCount}</td><td>{m.WarningCount}</td></tr>");
        }
        sb.AppendLine("</table>");

        // Improvements
        if (card.Improvements.Count > 0)
        {
            sb.AppendLine("<h2>✅ Improvements</h2><ul>");
            foreach (var imp in card.Improvements)
                sb.AppendLine($"<li class='imp'>↑ {Esc(imp.Category)}: {imp.PreviousGrade} → {imp.CurrentGrade} (+{imp.ScoreChange} pts)</li>");
            sb.AppendLine("</ul>");
        }

        // Regressions
        if (card.Regressions.Count > 0)
        {
            sb.AppendLine("<h2>⚠️ Regressions</h2><ul>");
            foreach (var reg in card.Regressions)
                sb.AppendLine($"<li class='reg'>↓ {Esc(reg.Category)}: {reg.PreviousGrade} → {reg.CurrentGrade} ({reg.ScoreChange} pts)</li>");
            sb.AppendLine("</ul>");
        }

        // Next steps
        if (card.NextSteps.Count > 0)
        {
            sb.AppendLine("<h2>📋 Next Steps</h2><ol>");
            foreach (var step in card.NextSteps)
                sb.AppendLine($"<li>{Esc(step)}</li>");
            sb.AppendLine("</ol>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    // ── Internals ────────────────────────────────────────────────

    public static double GradeToPoints(string grade) => grade switch
    {
        "A" => 4.0,
        "B" => 3.0,
        "C" => 2.0,
        "D" => 1.0,
        "F" => 0.0,
        _ => 0.0,
    };

    private static double ScoreToGpa(int score)
        => GradeToPoints(SecurityScorer.GetGrade(score));

    private static List<string> GenerateNextSteps(ReportCard card)
    {
        var steps = new List<string>();

        // Prioritise F-graded modules
        var fModules = card.Modules.Where(m => m.Grade == "F").ToList();
        if (fModules.Count > 0)
        {
            steps.Add($"URGENT: {fModules.Count} module(s) failing ({string.Join(", ", fModules.Select(m => m.Category))}) — address critical findings first");
        }

        // D-graded modules
        var dModules = card.Modules.Where(m => m.Grade == "D").ToList();
        if (dModules.Count > 0)
        {
            steps.Add($"Raise {dModules.Count} module(s) from D to C: {string.Join(", ", dModules.Select(m => m.Category))}");
        }

        // Worst regressions
        if (card.Regressions.Count > 0)
        {
            var worst = card.Regressions.First();
            steps.Add($"Investigate regression in {worst.Category} ({worst.PreviousGrade} → {worst.CurrentGrade}, {worst.ScoreChange} pts)");
        }

        // Modules with criticals
        var critModules = card.Modules.Where(m => m.CriticalCount > 0 && m.Grade != "F").ToList();
        if (critModules.Count > 0)
        {
            steps.Add($"Resolve critical findings in: {string.Join(", ", critModules.Select(m => $"{m.Category} ({m.CriticalCount})"))}");
        }

        // GPA target
        if (card.Gpa < 3.0)
            steps.Add($"Target GPA 3.00 (currently {card.Gpa:F2}) — focus on lowest-scoring modules");
        else if (card.Gpa < 3.5)
            steps.Add($"Target GPA 3.50 (currently {card.Gpa:F2}) — resolve remaining warnings");

        if (steps.Count == 0)
            steps.Add("Excellent posture! Maintain current practices and monitor for regressions.");

        return steps.Take(5).ToList();
    }

    private static string Esc(string s) =>
        System.Net.WebUtility.HtmlEncode(s);
}
