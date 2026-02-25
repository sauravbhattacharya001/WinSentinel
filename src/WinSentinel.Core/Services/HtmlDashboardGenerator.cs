using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Options for HTML dashboard generation.
/// </summary>
public class HtmlDashboardOptions
{
    public string Title { get; set; } = "WinSentinel Security Dashboard";
    public bool IncludePassedChecks { get; set; } = false;
    public bool DarkMode { get; set; } = false;
    public bool IncludeTimestamp { get; set; } = true;
    public bool CollapsibleSections { get; set; } = true;
    public string? CustomCss { get; set; }
}

/// <summary>
/// Generates a self-contained HTML dashboard report from security audit results.
/// </summary>
public class HtmlDashboardGenerator
{
    /// <summary>
    /// Generate a self-contained HTML dashboard from a SecurityReport.
    /// </summary>
    public string Generate(SecurityReport report, HtmlDashboardOptions? options = null)
    {
        options ??= new HtmlDashboardOptions();
        var sb = new StringBuilder();

        var score = SecurityScorer.CalculateScore(report);
        var grade = SecurityScorer.GetGrade(score);
        var scoreColor = GetDashboardScoreColor(score);
        var machineName = Environment.MachineName;
        var timestamp = report.GeneratedAt;

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html lang=\"en\" class=\"{(options.DarkMode ? "dark" : "light")}\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"<title>{HtmlEncode(options.Title)}</title>");
        sb.AppendLine("<style>");
        sb.Append(GenerateCss(options));
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("<header class=\"dashboard-header\">");
        sb.AppendLine($"<h1>{HtmlEncode(options.Title)}</h1>");
        sb.AppendLine("<div class=\"header-meta\">");
        sb.AppendLine($"<span class=\"machine-name\">Machine: {HtmlEncode(machineName)}</span>");
        if (options.IncludeTimestamp)
        {
            sb.AppendLine($"<span class=\"scan-timestamp\">Scanned: {timestamp:yyyy-MM-dd HH:mm:ss}</span>");
        }
        sb.AppendLine("<span class=\"version\">WinSentinel v1.0</span>");
        sb.AppendLine("</div>");
        sb.AppendLine("</header>");

        // Score Overview
        sb.AppendLine("<section class=\"score-overview\">");
        sb.AppendLine($"<div class=\"score-gauge\" style=\"--score: {score}; --score-color: {scoreColor}\">");
        sb.AppendLine($"<div class=\"score-value\">{score}</div>");
        sb.AppendLine($"<div class=\"score-grade grade-{grade.ToLowerInvariant()}\">{grade}</div>");
        sb.AppendLine("</div>");
        sb.AppendLine("</section>");

        // Summary Cards
        var totalFindings = report.TotalFindings;
        var critical = report.TotalCritical;
        var warning = report.TotalWarnings;
        var info = report.TotalInfo;
        var pass = report.TotalPass;
        var modules = report.Results.Count;

        sb.AppendLine("<section class=\"summary-cards\">");
        sb.AppendLine($"<div class=\"card\"><div class=\"card-value\">{totalFindings}</div><div class=\"card-label\">Total Findings</div></div>");
        sb.AppendLine($"<div class=\"card card-critical\"><div class=\"card-value\">{critical}</div><div class=\"card-label\">Critical</div></div>");
        sb.AppendLine($"<div class=\"card card-warning\"><div class=\"card-value\">{warning}</div><div class=\"card-label\">Warning</div></div>");
        sb.AppendLine($"<div class=\"card card-info\"><div class=\"card-value\">{info}</div><div class=\"card-label\">Info</div></div>");
        sb.AppendLine($"<div class=\"card card-pass\"><div class=\"card-value\">{pass}</div><div class=\"card-label\">Pass</div></div>");
        sb.AppendLine($"<div class=\"card\"><div class=\"card-value\">{modules}</div><div class=\"card-label\">Modules Scanned</div></div>");
        sb.AppendLine("</section>");

        // Severity Distribution
        var maxCount = Math.Max(1, new[] { critical, warning, info, pass }.Max());
        sb.AppendLine("<section class=\"severity-distribution\">");
        sb.AppendLine("<h2>Severity Distribution</h2>");
        sb.AppendLine("<div class=\"bar-chart\">");
        sb.AppendLine($"<div class=\"bar-row\"><span class=\"bar-label\">Critical</span><div class=\"bar\" style=\"width: {(critical * 100 / maxCount)}%; background: #dc2626;\">{critical}</div></div>");
        sb.AppendLine($"<div class=\"bar-row\"><span class=\"bar-label\">Warning</span><div class=\"bar\" style=\"width: {(warning * 100 / maxCount)}%; background: #f59e0b;\">{warning}</div></div>");
        sb.AppendLine($"<div class=\"bar-row\"><span class=\"bar-label\">Info</span><div class=\"bar\" style=\"width: {(info * 100 / maxCount)}%; background: #3b82f6;\">{info}</div></div>");
        sb.AppendLine($"<div class=\"bar-row\"><span class=\"bar-label\">Pass</span><div class=\"bar\" style=\"width: {(pass * 100 / maxCount)}%; background: #22c55e;\">{pass}</div></div>");
        sb.AppendLine("</div>");
        sb.AppendLine("</section>");

        // Module Breakdown Table
        sb.AppendLine("<section class=\"module-breakdown\">");
        sb.AppendLine("<h2>Module Breakdown</h2>");
        sb.AppendLine("<table class=\"module-table\">");
        sb.AppendLine("<thead><tr><th>Module</th><th>Score</th><th>Critical</th><th>Warning</th><th>Info</th><th>Pass</th><th>Status</th></tr></thead>");
        sb.AppendLine("<tbody>");
        foreach (var result in report.Results)
        {
            var modScore = SecurityScorer.CalculateCategoryScore(result);
            var status = result.OverallSeverity switch
            {
                Severity.Critical => "⚠ Critical",
                Severity.Warning => "⚡ Warning",
                Severity.Info => "ℹ Info",
                _ => "✅ Pass"
            };
            sb.AppendLine($"<tr><td>{HtmlEncode(result.ModuleName)}</td><td>{modScore}</td><td>{result.CriticalCount}</td><td>{result.WarningCount}</td><td>{result.InfoCount}</td><td>{result.PassCount}</td><td>{status}</td></tr>");
        }
        sb.AppendLine("</tbody>");
        sb.AppendLine("</table>");
        sb.AppendLine("</section>");

        // Findings Detail - grouped by module
        sb.AppendLine("<section class=\"findings-detail\">");
        sb.AppendLine("<h2>Findings</h2>");
        foreach (var result in report.Results)
        {
            var nonPassFindings = result.Findings.Where(f => f.Severity != Severity.Pass).ToList();
            if (nonPassFindings.Count == 0 && !options.IncludePassedChecks) continue;

            var findingsToShow = options.IncludePassedChecks ? result.Findings : nonPassFindings;
            if (findingsToShow.Count == 0) continue;

            if (options.CollapsibleSections)
            {
                sb.AppendLine($"<details open><summary>{HtmlEncode(result.ModuleName)} ({findingsToShow.Count} findings)</summary>");
            }
            else
            {
                sb.AppendLine($"<div class=\"module-group\"><h3>{HtmlEncode(result.ModuleName)}</h3>");
            }

            foreach (var finding in findingsToShow)
            {
                var severityClass = finding.Severity.ToString().ToLowerInvariant();
                sb.AppendLine($"<div class=\"finding\">");
                sb.AppendLine($"<span class=\"severity-badge badge-{severityClass}\">{finding.Severity}</span>");
                sb.AppendLine($"<strong class=\"finding-title\">{HtmlEncode(finding.Title)}</strong>");
                sb.AppendLine($"<p class=\"finding-description\">{HtmlEncode(finding.Description)}</p>");
                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"<p class=\"finding-remediation\">Remediation: {HtmlEncode(finding.Remediation)}</p>");
                }
                if (!string.IsNullOrEmpty(finding.FixCommand))
                {
                    sb.AppendLine($"<code class=\"fix-command\">{HtmlEncode(finding.FixCommand)}</code>");
                }
                sb.AppendLine("</div>");
            }

            if (options.CollapsibleSections)
                sb.AppendLine("</details>");
            else
                sb.AppendLine("</div>");
        }
        sb.AppendLine("</section>");

        // Passed Checks (optional)
        var passedFindings = report.Results.SelectMany(r => r.Findings.Where(f => f.Severity == Severity.Pass)).ToList();
        if (options.IncludePassedChecks && passedFindings.Count > 0)
        {
            sb.AppendLine("<section class=\"passed-checks\">");
            sb.AppendLine("<details><summary>Passed Checks (" + passedFindings.Count + ")</summary>");
            sb.AppendLine("<ul>");
            foreach (var f in passedFindings)
            {
                sb.AppendLine($"<li class=\"passed-item\">{HtmlEncode(f.Title)}: {HtmlEncode(f.Description)}</li>");
            }
            sb.AppendLine("</ul>");
            sb.AppendLine("</details>");
            sb.AppendLine("</section>");
        }

        // Footer
        sb.AppendLine("<footer class=\"dashboard-footer\">");
        if (options.IncludeTimestamp)
        {
            sb.AppendLine($"<p>Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>");
        }
        sb.AppendLine("<p>Powered by WinSentinel</p>");
        sb.AppendLine("</footer>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    /// <summary>
    /// Save HTML dashboard to a file (UTF-8, no BOM).
    /// </summary>
    public void SaveDashboard(string html, string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(filePath, html, new UTF8Encoding(false));
    }

    /// <summary>
    /// Generate a filename for the dashboard based on the report.
    /// </summary>
    public string GenerateFilename(SecurityReport report)
    {
        var date = report.GeneratedAt.ToString("yyyy-MM-dd");
        var machine = Environment.MachineName;
        return $"WinSentinel-{machine}-{date}.html";
    }

    public static string GetDashboardScoreColor(int score) => score switch
    {
        >= 90 => "#22c55e",
        >= 70 => "#eab308",
        >= 50 => "#f97316",
        _ => "#ef4444"
    };

    public static string HtmlEncode(string text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;");
    }

    private static string GenerateCss(HtmlDashboardOptions options)
    {
        var sb = new StringBuilder();
        sb.AppendLine(@"
:root {
    --bg: #ffffff;
    --text: #1a1a2e;
    --card-bg: #f8f9fa;
    --border: #e2e8f0;
    --header-bg: #1a1a2e;
    --header-text: #ffffff;
}
html.dark {
    --bg: #1a1a2e;
    --text: #e2e8f0;
    --card-bg: #16213e;
    --border: #334155;
    --header-bg: #0f0f23;
    --header-text: #e2e8f0;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}
.dashboard-header {
    background: var(--header-bg);
    color: var(--header-text);
    padding: 2rem;
    border-radius: 12px;
    margin-bottom: 2rem;
}
.dashboard-header h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
.header-meta { display: flex; gap: 2rem; font-size: 0.9rem; opacity: 0.8; flex-wrap: wrap; }
.score-overview { text-align: center; margin: 2rem 0; }
.score-gauge {
    width: 160px; height: 160px;
    border-radius: 50%;
    background: conic-gradient(var(--score-color) calc(var(--score) * 3.6deg), var(--border) 0);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
    position: relative;
}
.score-gauge::before {
    content: '';
    position: absolute;
    width: 120px; height: 120px;
    border-radius: 50%;
    background: var(--bg);
}
.score-value, .score-grade { position: relative; z-index: 1; }
.score-value { font-size: 2.5rem; font-weight: 700; }
.score-grade { font-size: 1.2rem; font-weight: 600; }
.summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 2rem 0; }
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }
.card-value { font-size: 2rem; font-weight: 700; }
.card-label { font-size: 0.85rem; opacity: 0.7; margin-top: 0.3rem; }
.card-critical .card-value { color: #dc2626; }
.card-warning .card-value { color: #f59e0b; }
.card-info .card-value { color: #3b82f6; }
.card-pass .card-value { color: #22c55e; }
.bar-chart { margin: 1rem 0; }
.bar-row { display: flex; align-items: center; margin: 0.5rem 0; }
.bar-label { width: 80px; font-size: 0.85rem; }
.bar { padding: 4px 8px; color: #fff; border-radius: 4px; min-width: 30px; font-size: 0.85rem; }
.module-table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
.module-table th, .module-table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
.module-table th { background: var(--card-bg); font-weight: 600; }
h2 { margin: 2rem 0 1rem; font-size: 1.4rem; }
details { margin: 1rem 0; }
summary { cursor: pointer; font-weight: 600; padding: 0.5rem 0; }
.finding { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 0.75rem 0; }
.severity-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: #fff; margin-right: 0.5rem; }
.badge-critical { background: #dc2626; }
.badge-warning { background: #f59e0b; }
.badge-info { background: #3b82f6; }
.badge-pass { background: #22c55e; }
.finding-title { font-size: 1rem; }
.finding-description { margin: 0.5rem 0; font-size: 0.9rem; }
.finding-remediation { font-size: 0.85rem; color: #6b7280; }
.fix-command { display: block; background: #1e293b; color: #e2e8f0; padding: 0.5rem 1rem; border-radius: 4px; margin-top: 0.5rem; font-family: monospace; overflow-x: auto; }
.passed-checks ul { list-style: none; padding: 0; }
.passed-item { padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
.dashboard-footer { text-align: center; margin-top: 3rem; padding: 1.5rem; border-top: 1px solid var(--border); font-size: 0.85rem; opacity: 0.6; }
@media (max-width: 768px) {
    body { padding: 1rem; }
    .summary-cards { grid-template-columns: repeat(2, 1fr); }
    .header-meta { flex-direction: column; gap: 0.5rem; }
}
@media print {
    body { padding: 0; }
    .dashboard-header { break-after: avoid; }
    details { open: true; }
    .score-gauge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    .severity-badge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}");
        if (!string.IsNullOrEmpty(options.CustomCss))
        {
            sb.AppendLine(options.CustomCss);
        }
        return sb.ToString();
    }
}
