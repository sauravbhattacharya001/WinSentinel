using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates security reports in HTML, JSON, and plain-text formats.
/// </summary>
public class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Generate a standalone HTML report with dark-theme styling.
    /// </summary>
    public string GenerateHtmlReport(SecurityReport report, ScoreTrendSummary? trend = null)
    {
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var gradeColor = SecurityScorer.GetScoreColor(report.SecurityScore);
        var machineName = Environment.MachineName;
        var generatedAt = report.GeneratedAt.ToLocalTime();

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"<title>WinSentinel Security Report — {generatedAt:yyyy-MM-dd}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetCss());
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("<header>");
        sb.AppendLine("  <div class=\"header-content\">");
        sb.AppendLine("    <div class=\"logo\">🛡️ <span>WinSentinel</span></div>");
        sb.AppendLine($"    <div class=\"header-info\">");
        sb.AppendLine($"      <div class=\"machine-name\">📍 {HtmlEncode(machineName)}</div>");
        sb.AppendLine($"      <div class=\"report-date\">📅 {generatedAt:MMMM dd, yyyy — HH:mm}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</header>");

        sb.AppendLine("<main>");

        // Overall Score Card
        sb.AppendLine("<section class=\"score-card\">");
        sb.AppendLine("  <h2>Overall Security Score</h2>");
        sb.AppendLine("  <div class=\"score-display\">");
        sb.AppendLine($"    <div class=\"score-number\" style=\"color: {gradeColor}\">{report.SecurityScore}</div>");
        sb.AppendLine($"    <div class=\"grade-badge\" style=\"background: {gradeColor}\">{grade}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"score-bar-container\">");
        sb.AppendLine($"    <div class=\"score-bar\" style=\"width: {report.SecurityScore}%; background: {gradeColor}\"></div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"summary-stats\">");
        sb.AppendLine($"    <div class=\"stat\"><span class=\"stat-value critical-text\">{report.TotalCritical}</span><span class=\"stat-label\">Critical</span></div>");
        sb.AppendLine($"    <div class=\"stat\"><span class=\"stat-value warning-text\">{report.TotalWarnings}</span><span class=\"stat-label\">Warnings</span></div>");
        sb.AppendLine($"    <div class=\"stat\"><span class=\"stat-value info-text\">{report.TotalInfo}</span><span class=\"stat-label\">Info</span></div>");
        sb.AppendLine($"    <div class=\"stat\"><span class=\"stat-value pass-text\">{report.TotalPass}</span><span class=\"stat-label\">Pass</span></div>");
        sb.AppendLine($"    <div class=\"stat\"><span class=\"stat-value\">{report.TotalFindings}</span><span class=\"stat-label\">Total</span></div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</section>");

        // Score Trend Chart (if history available)
        if (trend != null && trend.Points.Count > 1)
        {
            sb.AppendLine("<section class=\"trend-section\">");
            sb.AppendLine("  <h2>📈 Score Trend</h2>");
            sb.AppendLine("  <div class=\"trend-chart\">");

            var points = trend.Points.TakeLast(20).ToList();
            foreach (var point in points)
            {
                var barColor = SecurityScorer.GetScoreColor(point.Score);
                var barWidth = Math.Max(2, point.Score);
                sb.AppendLine($"    <div class=\"trend-row\">");
                sb.AppendLine($"      <span class=\"trend-date\">{point.Timestamp.ToLocalTime():MM/dd HH:mm}</span>");
                sb.AppendLine($"      <div class=\"trend-bar-container\">");
                sb.AppendLine($"        <div class=\"trend-bar\" style=\"width: {barWidth}%; background: {barColor}\"></div>");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <span class=\"trend-score\">{point.Score} ({point.Grade})</span>");
                sb.AppendLine($"    </div>");
            }

            sb.AppendLine("  </div>");

            // Trend stats
            sb.AppendLine("  <div class=\"trend-stats\">");
            if (trend.BestScore.HasValue)
                sb.AppendLine($"    <div class=\"trend-stat\">🏆 Best: <strong>{trend.BestScore} ({trend.BestScoreGrade})</strong> on {trend.BestScoreDate?.ToLocalTime():MMM dd}</div>");
            if (trend.WorstScore.HasValue)
                sb.AppendLine($"    <div class=\"trend-stat\">📉 Worst: <strong>{trend.WorstScore} ({trend.WorstScoreGrade})</strong> on {trend.WorstScoreDate?.ToLocalTime():MMM dd}</div>");
            sb.AppendLine($"    <div class=\"trend-stat\">📊 Average: <strong>{trend.AverageScore:F0}</strong> over {trend.TotalScans} scans</div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("</section>");
        }

        // Module Breakdown Table
        sb.AppendLine("<section class=\"module-breakdown\">");
        sb.AppendLine("  <h2>Module Breakdown</h2>");
        sb.AppendLine("  <table>");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr><th>Module</th><th>Score</th><th>Grade</th><th>Critical</th><th>Warnings</th><th>Findings</th><th>Status</th></tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            var modColor = SecurityScorer.GetScoreColor(modScore);
            var statusIcon = result.Success
                ? (modScore >= 80 ? "✅" : modScore >= 60 ? "⚠️" : "🔴")
                : "❌";

            sb.AppendLine("      <tr>");
            sb.AppendLine($"        <td class=\"module-name\">{HtmlEncode(result.Category)}</td>");
            sb.AppendLine($"        <td style=\"color: {modColor}; font-weight: bold\">{modScore}</td>");
            sb.AppendLine($"        <td><span class=\"grade-pill\" style=\"background: {modColor}\">{modGrade}</span></td>");
            sb.AppendLine($"        <td class=\"critical-text\">{result.CriticalCount}</td>");
            sb.AppendLine($"        <td class=\"warning-text\">{result.WarningCount}</td>");
            sb.AppendLine($"        <td>{result.Findings.Count}</td>");
            sb.AppendLine($"        <td>{statusIcon}</td>");
            sb.AppendLine("      </tr>");
        }

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</section>");

        // Detailed Findings per Module
        sb.AppendLine("<section class=\"detailed-findings\">");
        sb.AppendLine("  <h2>Detailed Findings</h2>");

        foreach (var result in report.Results)
        {
            if (result.Findings.Count == 0 && result.Success) continue;

            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modColor = SecurityScorer.GetScoreColor(modScore);

            sb.AppendLine($"  <div class=\"module-detail\">");
            sb.AppendLine($"    <h3><span class=\"module-indicator\" style=\"background: {modColor}\"></span> {HtmlEncode(result.Category)} <span class=\"module-score\" style=\"color: {modColor}\">{modScore}/100</span></h3>");

            if (!result.Success)
            {
                sb.AppendLine($"    <div class=\"finding-card error\">");
                sb.AppendLine($"      <div class=\"finding-header\">❌ Module Error</div>");
                sb.AppendLine($"      <div class=\"finding-desc\">{HtmlEncode(result.Error ?? "Unknown error")}</div>");
                sb.AppendLine($"    </div>");
            }

            // Group findings by severity (Critical first, then Warning, Info, Pass)
            var orderedFindings = result.Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Title);

            foreach (var finding in orderedFindings)
            {
                var severityClass = finding.Severity.ToString().ToLowerInvariant();
                var severityIcon = finding.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.Warning => "🟡",
                    Severity.Info => "🔵",
                    Severity.Pass => "✅",
                    _ => "ℹ️"
                };

                sb.AppendLine($"    <div class=\"finding-card {severityClass}\">");
                sb.AppendLine($"      <div class=\"finding-header\">{severityIcon} <span class=\"severity-badge {severityClass}\">{finding.Severity}</span> {HtmlEncode(finding.Title)}</div>");
                sb.AppendLine($"      <div class=\"finding-desc\">{HtmlEncode(finding.Description)}</div>");

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"      <div class=\"remediation\">💡 <strong>Remediation:</strong> {HtmlEncode(finding.Remediation)}</div>");
                }

                sb.AppendLine($"    </div>");
            }

            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</section>");

        sb.AppendLine("</main>");

        // Footer
        sb.AppendLine("<footer>");
        sb.AppendLine($"  <p>Generated by WinSentinel v1.0 on {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}</p>");
        sb.AppendLine($"  <p>Machine: {HtmlEncode(machineName)} | Total Modules: {report.Results.Count} | Total Findings: {report.TotalFindings}</p>");
        sb.AppendLine("</footer>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    /// <summary>
    /// Generate a structured JSON report.
    /// </summary>
    public string GenerateJsonReport(SecurityReport report, ScoreTrendSummary? trend = null)
    {
        var export = new JsonReportModel
        {
            ReportVersion = "1.0",
            GeneratedAt = report.GeneratedAt,
            MachineName = Environment.MachineName,
            OverallScore = report.SecurityScore,
            Grade = SecurityScorer.GetGrade(report.SecurityScore),
            Summary = new JsonReportSummary
            {
                TotalFindings = report.TotalFindings,
                Critical = report.TotalCritical,
                Warnings = report.TotalWarnings,
                Info = report.TotalInfo,
                Pass = report.TotalPass
            },
            Modules = report.Results.Select(r => new JsonModuleResult
            {
                Name = r.ModuleName,
                Category = r.Category,
                Score = SecurityScorer.CalculateCategoryScore(r),
                Grade = SecurityScorer.GetGrade(SecurityScorer.CalculateCategoryScore(r)),
                Success = r.Success,
                Error = r.Error,
                Duration = r.Duration.TotalSeconds,
                Findings = r.Findings.Select(f => new JsonFinding
                {
                    Title = f.Title,
                    Description = f.Description,
                    Severity = f.Severity.ToString(),
                    Remediation = f.Remediation,
                    FixCommand = f.FixCommand,
                    Category = f.Category,
                    Timestamp = f.Timestamp
                }).ToList()
            }).ToList()
        };

        if (trend != null && trend.Points.Count > 0)
        {
            export.Trend = new JsonTrendData
            {
                TotalScans = trend.TotalScans,
                AverageScore = Math.Round(trend.AverageScore, 1),
                BestScore = trend.BestScore,
                WorstScore = trend.WorstScore,
                Points = trend.Points.Select(p => new JsonTrendPoint
                {
                    Timestamp = p.Timestamp,
                    Score = p.Score,
                    Grade = p.Grade
                }).ToList()
            };
        }

        return JsonSerializer.Serialize(export, JsonOptions);
    }

    /// <summary>
    /// Generate a plain-text report suitable for CLI output or email.
    /// </summary>
    public string GenerateTextReport(SecurityReport report, ScoreTrendSummary? trend = null)
    {
        var sb = new StringBuilder();
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var generatedAt = report.GeneratedAt.ToLocalTime();

        // Header
        sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║              WinSentinel Security Report                    ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Machine:    {Environment.MachineName}");
        sb.AppendLine($"  Date:       {generatedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Score:      {report.SecurityScore}/100 (Grade: {grade})");
        sb.AppendLine();

        // Summary
        sb.AppendLine("── Summary ──────────────────────────────────────────────────────");
        sb.AppendLine($"  Critical:   {report.TotalCritical}");
        sb.AppendLine($"  Warnings:   {report.TotalWarnings}");
        sb.AppendLine($"  Info:       {report.TotalInfo}");
        sb.AppendLine($"  Pass:       {report.TotalPass}");
        sb.AppendLine($"  Total:      {report.TotalFindings}");
        sb.AppendLine();

        // Module Breakdown
        sb.AppendLine("── Module Breakdown ─────────────────────────────────────────────");
        sb.AppendLine();
        sb.AppendLine($"  {"Module",-25} {"Score",-8} {"Grade",-7} {"Critical",-10} {"Warnings",-10} {"Status",-8}");
        sb.AppendLine($"  {new string('─', 25)} {new string('─', 6)} {new string('─', 5)} {new string('─', 8)} {new string('─', 8)} {new string('─', 6)}");

        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            var status = result.Success ? (modScore >= 80 ? "OK" : modScore >= 60 ? "WARN" : "FAIL") : "ERROR";

            sb.AppendLine($"  {result.Category,-25} {modScore,-8} {modGrade,-7} {result.CriticalCount,-10} {result.WarningCount,-10} {status,-8}");
        }

        sb.AppendLine();

        // Trend data
        if (trend != null && trend.Points.Count > 1)
        {
            sb.AppendLine("── Score Trend ──────────────────────────────────────────────────");
            sb.AppendLine();

            var points = trend.Points.TakeLast(10).ToList();
            foreach (var point in points)
            {
                var barLen = (int)(point.Score / 5.0);
                var bar = new string('█', barLen);
                var pad = new string('░', 20 - barLen);
                sb.AppendLine($"  {point.Timestamp.ToLocalTime():MM/dd HH:mm}  {bar}{pad}  {point.Score} ({point.Grade})");
            }

            sb.AppendLine();
            if (trend.BestScore.HasValue)
                sb.AppendLine($"  Best:    {trend.BestScore} ({trend.BestScoreGrade}) on {trend.BestScoreDate?.ToLocalTime():MMM dd}");
            if (trend.WorstScore.HasValue)
                sb.AppendLine($"  Worst:   {trend.WorstScore} ({trend.WorstScoreGrade}) on {trend.WorstScoreDate?.ToLocalTime():MMM dd}");
            sb.AppendLine($"  Average: {trend.AverageScore:F0} over {trend.TotalScans} scans");
            sb.AppendLine();
        }

        // Detailed Findings
        sb.AppendLine("── Detailed Findings ────────────────────────────────────────────");

        foreach (var result in report.Results)
        {
            if (result.Findings.Count == 0 && result.Success) continue;

            var modScore = SecurityScorer.CalculateCategoryScore(result);
            sb.AppendLine();
            sb.AppendLine($"  ┌─ {result.Category} (Score: {modScore}/100)");

            if (!result.Success)
            {
                sb.AppendLine($"  │  [ERROR] {result.Error ?? "Unknown error"}");
            }

            var orderedFindings = result.Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Title);

            foreach (var finding in orderedFindings)
            {
                var icon = finding.Severity switch
                {
                    Severity.Critical => "[CRITICAL]",
                    Severity.Warning => "[WARNING] ",
                    Severity.Info => "[INFO]    ",
                    Severity.Pass => "[PASS]    ",
                    _ => "[?]       "
                };

                sb.AppendLine($"  │");
                sb.AppendLine($"  │  {icon} {finding.Title}");
                sb.AppendLine($"  │    {finding.Description}");

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"  │    → Fix: {finding.Remediation}");
                }
            }

            sb.AppendLine("  └─────────────────────────────────────────────────");
        }

        sb.AppendLine();
        sb.AppendLine("══════════════════════════════════════════════════════════════════");
        sb.AppendLine($"  Generated: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"  WinSentinel v1.0");
        sb.AppendLine("══════════════════════════════════════════════════════════════════");

        return sb.ToString();
    }

    /// <summary>
    /// Generate a GitHub-flavored Markdown report.
    /// Ideal for sharing in GitHub Issues, PRs, wikis, Slack, documentation, and CI/CD artifacts.
    /// </summary>
    public string GenerateMarkdownReport(SecurityReport report, ScoreTrendSummary? trend = null)
    {
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var gradeEmoji = GetGradeEmoji(grade);
        var generatedAt = report.GeneratedAt.ToLocalTime();
        var machineName = Environment.MachineName;

        var sb = new StringBuilder();

        // Title
        sb.AppendLine("# 🛡️ WinSentinel Security Report");
        sb.AppendLine();
        sb.AppendLine($"> **Machine:** `{machineName}` · **Date:** {generatedAt:yyyy-MM-dd HH:mm} · **Modules:** {report.Results.Count}");
        sb.AppendLine();

        // Overall Score
        sb.AppendLine("## Overall Score");
        sb.AppendLine();
        sb.AppendLine($"{gradeEmoji} **{report.SecurityScore}/100** — Grade **{grade}**");
        sb.AppendLine();

        // Score bar (rendered as text progress bar)
        var filled = report.SecurityScore / 5;
        var empty = 20 - filled;
        sb.AppendLine($"`[{"█".PadRight(filled, '█').PadRight(20, '░')}]` {report.SecurityScore}%");
        sb.AppendLine();

        // Summary stats table
        sb.AppendLine("### Summary");
        sb.AppendLine();
        sb.AppendLine("| 🔴 Critical | 🟡 Warnings | 🔵 Info | ✅ Pass | Total |");
        sb.AppendLine("|:-----------:|:-----------:|:-------:|:------:|:-----:|");
        sb.AppendLine($"| **{report.TotalCritical}** | **{report.TotalWarnings}** | **{report.TotalInfo}** | **{report.TotalPass}** | **{report.TotalFindings}** |");
        sb.AppendLine();

        // Score Trend (if available)
        if (trend != null && trend.Points.Count > 1)
        {
            sb.AppendLine("## 📈 Score Trend");
            sb.AppendLine();

            var points = trend.Points.TakeLast(15).ToList();
            sb.AppendLine("| Date | Score | Grade | Trend |");
            sb.AppendLine("|:-----|------:|:-----:|:------|");

            for (int i = 0; i < points.Count; i++)
            {
                var point = points[i];
                var trendBar = new string('█', point.Score / 5);
                var changeStr = "";
                if (i > 0)
                {
                    var change = point.Score - points[i - 1].Score;
                    changeStr = change > 0 ? $" ↑{change}" : change < 0 ? $" ↓{Math.Abs(change)}" : "";
                }
                sb.AppendLine($"| {point.Timestamp.ToLocalTime():MM/dd HH:mm} | **{point.Score}** | {point.Grade} | `{trendBar}`{changeStr} |");
            }
            sb.AppendLine();

            // Trend stats
            if (trend.BestScore.HasValue)
                sb.AppendLine($"- 🏆 **Best:** {trend.BestScore} ({trend.BestScoreGrade}) on {trend.BestScoreDate?.ToLocalTime():MMM dd, yyyy}");
            if (trend.WorstScore.HasValue)
                sb.AppendLine($"- 📉 **Worst:** {trend.WorstScore} ({trend.WorstScoreGrade}) on {trend.WorstScoreDate?.ToLocalTime():MMM dd, yyyy}");
            sb.AppendLine($"- 📊 **Average:** {trend.AverageScore:F0} over {trend.TotalScans} scans");
            sb.AppendLine();
        }

        // Module Breakdown
        sb.AppendLine("## Module Breakdown");
        sb.AppendLine();
        sb.AppendLine("| Module | Score | Grade | Critical | Warnings | Findings | Status |");
        sb.AppendLine("|:-------|------:|:-----:|---------:|---------:|---------:|:------:|");

        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            var statusIcon = result.Success
                ? (modScore >= 80 ? "✅" : modScore >= 60 ? "⚠️" : "🔴")
                : "❌";

            sb.AppendLine($"| {result.Category} | **{modScore}** | {modGrade} | {result.CriticalCount} | {result.WarningCount} | {result.Findings.Count} | {statusIcon} |");
        }

        sb.AppendLine();

        // Detailed Findings
        sb.AppendLine("## Detailed Findings");
        sb.AppendLine();

        foreach (var result in report.Results)
        {
            // Only show modules with actionable findings or errors
            var actionableFindings = result.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Title)
                .ToList();

            if (actionableFindings.Count == 0 && result.Success) continue;

            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var modGrade = SecurityScorer.GetGrade(modScore);
            sb.AppendLine($"### {result.Category} — {modScore}/100 ({modGrade})");
            sb.AppendLine();

            if (!result.Success)
            {
                sb.AppendLine($"> ❌ **Module Error:** {result.Error ?? "Unknown error"}");
                sb.AppendLine();
            }

            foreach (var finding in actionableFindings)
            {
                var severityEmoji = finding.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.Warning => "🟡",
                    _ => "🔵"
                };
                var severityLabel = finding.Severity switch
                {
                    Severity.Critical => "CRITICAL",
                    Severity.Warning => "WARNING",
                    _ => "INFO"
                };

                sb.AppendLine($"- {severityEmoji} **[{severityLabel}]** {finding.Title}");
                sb.AppendLine($"  - {finding.Description}");

                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"  - 💡 *{finding.Remediation}*");
                }

                if (!string.IsNullOrEmpty(finding.FixCommand))
                {
                    sb.AppendLine($"  - 🔧 `{finding.FixCommand}`");
                }
            }

            sb.AppendLine();
        }

        // Passed checks (collapsible)
        var passedChecks = report.Results
            .SelectMany(r => r.Findings.Where(f => f.Severity == Severity.Pass))
            .ToList();

        if (passedChecks.Count > 0)
        {
            sb.AppendLine("<details>");
            sb.AppendLine($"<summary>✅ Passed Checks ({passedChecks.Count})</summary>");
            sb.AppendLine();

            foreach (var result in report.Results)
            {
                var passes = result.Findings.Where(f => f.Severity == Severity.Pass).ToList();
                if (passes.Count == 0) continue;

                sb.AppendLine($"**{result.Category}**");
                foreach (var finding in passes)
                {
                    sb.AppendLine($"- ✅ {finding.Title}");
                }
                sb.AppendLine();
            }

            sb.AppendLine("</details>");
            sb.AppendLine();
        }

        // Info findings (collapsible)
        var infoFindings = report.Results
            .SelectMany(r => r.Findings.Where(f => f.Severity == Severity.Info))
            .ToList();

        if (infoFindings.Count > 0)
        {
            sb.AppendLine("<details>");
            sb.AppendLine($"<summary>🔵 Informational ({infoFindings.Count})</summary>");
            sb.AppendLine();

            foreach (var result in report.Results)
            {
                var infos = result.Findings.Where(f => f.Severity == Severity.Info).ToList();
                if (infos.Count == 0) continue;

                sb.AppendLine($"**{result.Category}**");
                foreach (var finding in infos)
                {
                    sb.AppendLine($"- 🔵 {finding.Title} — {finding.Description}");
                }
                sb.AppendLine();
            }

            sb.AppendLine("</details>");
            sb.AppendLine();
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine($"*Generated by [WinSentinel](https://github.com/sauravbhattacharya001/WinSentinel) v1.0 on {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}*");

        return sb.ToString();
    }

    /// <summary>
    /// Get an emoji representing the grade.
    /// </summary>
    private static string GetGradeEmoji(string grade) => grade switch
    {
        "A" => "🟢",
        "B" => "🟢",
        "C" => "🟡",
        "D" => "🟠",
        _ => "🔴"
    };

    /// <summary>
    /// Save a report to a file in the specified format.
    /// </summary>
    public void SaveReport(string filePath, SecurityReport report, ReportFormat format, ScoreTrendSummary? trend = null)
    {
        var content = format switch
        {
            ReportFormat.Html => GenerateHtmlReport(report, trend),
            ReportFormat.Json => GenerateJsonReport(report, trend),
            ReportFormat.Text => GenerateTextReport(report, trend),
            ReportFormat.Markdown => GenerateMarkdownReport(report, trend),
            _ => throw new ArgumentException($"Unknown report format: {format}", nameof(format))
        };

        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(filePath, content, Encoding.UTF8);
    }

    /// <summary>
    /// Generate a filename for auto-export reports.
    /// </summary>
    public static string GenerateFilename(ReportFormat format, DateTimeOffset? timestamp = null)
    {
        var ts = timestamp ?? DateTimeOffset.Now;
        var extension = format switch
        {
            ReportFormat.Html => "html",
            ReportFormat.Json => "json",
            ReportFormat.Text => "txt",
            ReportFormat.Markdown => "md",
            _ => "html"
        };
        return $"WinSentinel-Report-{ts:yyyy-MM-dd-HHmm}.{extension}";
    }

    private static string HtmlEncode(string text)
    {
        return System.Net.WebUtility.HtmlEncode(text);
    }

    private static string GetCss()
    {
        return @"
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    line-height: 1.6;
    padding: 0;
}
header {
    background: linear-gradient(135deg, #161b22 0%, #1a2233 100%);
    border-bottom: 1px solid #30363d;
    padding: 24px 40px;
}
.header-content {
    max-width: 1000px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.logo {
    font-size: 28px;
    font-weight: 700;
    color: #58a6ff;
}
.logo span { margin-left: 8px; }
.header-info { text-align: right; color: #8b949e; font-size: 14px; }
.machine-name { font-weight: 600; color: #c9d1d9; }
main {
    max-width: 1000px;
    margin: 0 auto;
    padding: 32px 40px;
}
section {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}
h2 {
    font-size: 20px;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
}
h3 {
    font-size: 16px;
    font-weight: 600;
    color: #c9d1d9;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.score-card { text-align: center; }
.score-display {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 16px;
    margin-bottom: 16px;
}
.score-number {
    font-size: 72px;
    font-weight: 800;
    line-height: 1;
}
.grade-badge {
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    padding: 8px 20px;
    border-radius: 12px;
    text-shadow: 0 1px 2px rgba(0,0,0,0.3);
}
.score-bar-container {
    background: #21262d;
    border-radius: 8px;
    height: 12px;
    max-width: 400px;
    margin: 0 auto 20px;
    overflow: hidden;
}
.score-bar {
    height: 100%;
    border-radius: 8px;
    transition: width 0.5s ease;
}
.summary-stats {
    display: flex;
    justify-content: center;
    gap: 32px;
    flex-wrap: wrap;
}
.stat { text-align: center; }
.stat-value {
    display: block;
    font-size: 24px;
    font-weight: 700;
    color: #e6edf3;
}
.stat-label {
    font-size: 13px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.critical-text { color: #f85149 !important; }
.warning-text { color: #d29922 !important; }
.info-text { color: #58a6ff !important; }
.pass-text { color: #3fb950 !important; }

/* Table */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
}
thead th {
    text-align: left;
    padding: 10px 12px;
    background: #21262d;
    color: #8b949e;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 12px;
    letter-spacing: 0.5px;
    border-bottom: 1px solid #30363d;
}
thead th:first-child { border-radius: 8px 0 0 0; }
thead th:last-child { border-radius: 0 8px 0 0; }
tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #21262d;
}
tbody tr:hover { background: #1c2128; }
.module-name { font-weight: 600; color: #e6edf3; }
.grade-pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    color: #fff;
    font-weight: 700;
    font-size: 12px;
    text-shadow: 0 1px 1px rgba(0,0,0,0.3);
}

/* Findings */
.module-detail {
    margin-bottom: 20px;
    padding: 16px;
    background: #0d1117;
    border-radius: 8px;
    border: 1px solid #21262d;
}
.module-indicator {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
}
.module-score {
    font-size: 14px;
    font-weight: 400;
    margin-left: auto;
}
.finding-card {
    padding: 12px 16px;
    margin: 8px 0;
    border-radius: 8px;
    border-left: 4px solid #30363d;
    background: #161b22;
}
.finding-card.critical { border-left-color: #f85149; }
.finding-card.warning { border-left-color: #d29922; }
.finding-card.info { border-left-color: #58a6ff; }
.finding-card.pass { border-left-color: #3fb950; }
.finding-card.error { border-left-color: #f85149; background: #2d1418; }
.finding-header {
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}
.severity-badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.severity-badge.critical { background: #f8514933; color: #f85149; }
.severity-badge.warning { background: #d2992233; color: #d29922; }
.severity-badge.info { background: #58a6ff33; color: #58a6ff; }
.severity-badge.pass { background: #3fb95033; color: #3fb950; }
.finding-desc {
    color: #8b949e;
    font-size: 14px;
    margin-bottom: 4px;
}
.remediation {
    color: #3fb950;
    font-size: 13px;
    margin-top: 6px;
    padding: 8px 12px;
    background: #3fb95010;
    border-radius: 6px;
    border: 1px solid #3fb95030;
}

/* Trend */
.trend-chart { margin-bottom: 16px; }
.trend-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 4px;
    font-size: 13px;
}
.trend-date {
    min-width: 100px;
    color: #8b949e;
    font-family: 'Cascadia Mono', 'Consolas', monospace;
}
.trend-bar-container {
    flex: 1;
    background: #21262d;
    border-radius: 4px;
    height: 16px;
    overflow: hidden;
}
.trend-bar {
    height: 100%;
    border-radius: 4px;
    min-width: 2px;
}
.trend-score {
    min-width: 70px;
    text-align: right;
    font-weight: 600;
    color: #c9d1d9;
}
.trend-stats {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    font-size: 14px;
    color: #8b949e;
}
.trend-stat strong { color: #c9d1d9; }

/* Footer */
footer {
    max-width: 1000px;
    margin: 0 auto;
    padding: 24px 40px 48px;
    text-align: center;
    color: #484f58;
    font-size: 13px;
    border-top: 1px solid #21262d;
}
footer p { margin: 4px 0; }

@media (max-width: 700px) {
    header, main, footer { padding-left: 16px; padding-right: 16px; }
    .header-content { flex-direction: column; gap: 8px; }
    .header-info { text-align: left; }
    .score-number { font-size: 48px; }
    .summary-stats { gap: 16px; }
    .trend-stats { flex-direction: column; gap: 8px; }
}
";
    }

    // ── JSON Report Models ──────────────────────────────────────────
    private class JsonReportModel
    {
        [JsonPropertyName("reportVersion")]
        public string ReportVersion { get; set; } = "";

        [JsonPropertyName("generatedAt")]
        public DateTimeOffset GeneratedAt { get; set; }

        [JsonPropertyName("machineName")]
        public string MachineName { get; set; } = "";

        [JsonPropertyName("overallScore")]
        public int OverallScore { get; set; }

        [JsonPropertyName("grade")]
        public string Grade { get; set; } = "";

        [JsonPropertyName("summary")]
        public JsonReportSummary Summary { get; set; } = new();

        [JsonPropertyName("modules")]
        public List<JsonModuleResult> Modules { get; set; } = [];

        [JsonPropertyName("trend")]
        public JsonTrendData? Trend { get; set; }
    }

    private class JsonReportSummary
    {
        [JsonPropertyName("totalFindings")]
        public int TotalFindings { get; set; }

        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("warnings")]
        public int Warnings { get; set; }

        [JsonPropertyName("info")]
        public int Info { get; set; }

        [JsonPropertyName("pass")]
        public int Pass { get; set; }
    }

    private class JsonModuleResult
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("category")]
        public string Category { get; set; } = "";

        [JsonPropertyName("score")]
        public int Score { get; set; }

        [JsonPropertyName("grade")]
        public string Grade { get; set; } = "";

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("durationSeconds")]
        public double Duration { get; set; }

        [JsonPropertyName("findings")]
        public List<JsonFinding> Findings { get; set; } = [];
    }

    private class JsonFinding
    {
        [JsonPropertyName("title")]
        public string Title { get; set; } = "";

        [JsonPropertyName("description")]
        public string Description { get; set; } = "";

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "";

        [JsonPropertyName("remediation")]
        public string? Remediation { get; set; }

        [JsonPropertyName("fixCommand")]
        public string? FixCommand { get; set; }

        [JsonPropertyName("category")]
        public string Category { get; set; } = "";

        [JsonPropertyName("timestamp")]
        public DateTimeOffset Timestamp { get; set; }
    }

    private class JsonTrendData
    {
        [JsonPropertyName("totalScans")]
        public int TotalScans { get; set; }

        [JsonPropertyName("averageScore")]
        public double AverageScore { get; set; }

        [JsonPropertyName("bestScore")]
        public int? BestScore { get; set; }

        [JsonPropertyName("worstScore")]
        public int? WorstScore { get; set; }

        [JsonPropertyName("points")]
        public List<JsonTrendPoint> Points { get; set; } = [];
    }

    private class JsonTrendPoint
    {
        [JsonPropertyName("timestamp")]
        public DateTimeOffset Timestamp { get; set; }

        [JsonPropertyName("score")]
        public int Score { get; set; }

        [JsonPropertyName("grade")]
        public string Grade { get; set; } = "";
    }
}

/// <summary>
/// Supported report export formats.
/// </summary>
public enum ReportFormat
{
    Html,
    Json,
    Text,
    Markdown
}
