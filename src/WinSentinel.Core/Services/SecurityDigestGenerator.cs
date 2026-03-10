using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// A concise security digest — a newsletter-style summary comparing
/// current scan results against previous history, with trend indicators,
/// top risks, action items, and a health pulse rating.
/// Produces both plain-text and HTML output suitable for email or chat notifications.
/// </summary>
public class SecurityDigestGenerator
{
    private readonly AuditHistoryService _historyService;

    public SecurityDigestGenerator(AuditHistoryService historyService)
    {
        _historyService = historyService;
    }

    /// <summary>
    /// Generate a digest from a current report and optional history lookback.
    /// </summary>
    public SecurityDigest Generate(SecurityReport currentReport, int historyDays = 30)
    {
        var history = _historyService.GetRecentRuns(historyDays);
        var previousRun = history.Count > 0 ? history[0] : null;

        var digest = new SecurityDigest
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            MachineName = Environment.MachineName,
            CurrentScore = currentReport.SecurityScore,
            CurrentGrade = SecurityScorer.GetGrade(currentReport.SecurityScore),
            PreviousScore = previousRun?.OverallScore,
            PreviousGrade = previousRun != null ? SecurityScorer.GetGrade(previousRun.OverallScore) : null,
            TotalFindings = currentReport.TotalFindings,
            CriticalCount = currentReport.TotalCritical,
            WarningCount = currentReport.TotalWarnings,
            InfoCount = currentReport.TotalInfo,
            PassCount = currentReport.TotalPass,
            ModulesScanned = currentReport.Results.Count,
            ScanDuration = currentReport.Results.Count > 0
                ? TimeSpan.FromTicks(currentReport.Results.Sum(r => r.Duration.Ticks))
                : TimeSpan.Zero,
        };

        // Trend calculation
        if (previousRun != null)
        {
            digest.ScoreDelta = digest.CurrentScore - previousRun.OverallScore;
            digest.CriticalDelta = digest.CriticalCount - previousRun.CriticalCount;
            digest.WarningDelta = digest.WarningCount - previousRun.WarningCount;
            digest.Trend = digest.ScoreDelta switch
            {
                > 5 => DigestTrend.Improving,
                < -5 => DigestTrend.Declining,
                _ => DigestTrend.Stable
            };
        }

        // Health pulse
        digest.Pulse = ComputePulse(digest);

        // Top risks (critical first, then warnings, max 5)
        digest.TopRisks = currentReport.Results
            .SelectMany(r => r.Findings.Select(f => new DigestRiskItem
            {
                Title = f.Title,
                Severity = f.Severity,
                Category = f.Category,
                HasAutoFix = !string.IsNullOrWhiteSpace(f.FixCommand),
                Remediation = f.Remediation
            }))
            .Where(r => r.Severity is Severity.Critical or Severity.Warning)
            .OrderByDescending(r => r.Severity == Severity.Critical ? 1 : 0)
            .ThenBy(r => r.Title)
            .Take(5)
            .ToList();

        // Module breakdown
        digest.ModuleBreakdown = currentReport.Results
            .Select(r => new DigestModuleEntry
            {
                ModuleName = r.ModuleName,
                Category = r.Category,
                Score = r.Score,
                CriticalCount = r.CriticalCount,
                WarningCount = r.WarningCount,
                Status = r.CriticalCount > 0 ? "⚠️ Critical" :
                         r.WarningCount > 0 ? "⚡ Warning" : "✅ Clean"
            })
            .OrderBy(m => m.Score)
            .ToList();

        // Weakest and strongest modules
        if (digest.ModuleBreakdown.Count > 0)
        {
            digest.WeakestModule = digest.ModuleBreakdown.First().ModuleName;
            digest.StrongestModule = digest.ModuleBreakdown.Last().ModuleName;
        }

        // History sparkline (last N scores)
        digest.ScoreHistory = history
            .Take(10)
            .Select(r => r.OverallScore)
            .Reverse()
            .ToList();

        // Action summary
        var autoFixCount = currentReport.Results
            .SelectMany(r => r.Findings)
            .Count(f => !string.IsNullOrWhiteSpace(f.FixCommand) &&
                        f.Severity is Severity.Critical or Severity.Warning);
        digest.AutoFixableCount = autoFixCount;
        digest.ManualActionCount = digest.CriticalCount + digest.WarningCount - autoFixCount;

        // New findings (in current but not in previous, by title)
        if (previousRun != null)
        {
            var previousTitles = new HashSet<string>(
                previousRun.Findings.Select(f => f.Title),
                StringComparer.OrdinalIgnoreCase);

            digest.NewFindings = currentReport.Results
                .SelectMany(r => r.Findings)
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .Where(f => !previousTitles.Contains(f.Title))
                .Select(f => f.Title)
                .Distinct()
                .Take(5)
                .ToList();

            // Resolved findings
            var currentTitles = new HashSet<string>(
                currentReport.Results
                    .SelectMany(r => r.Findings)
                    .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                    .Select(f => f.Title),
                StringComparer.OrdinalIgnoreCase);

            digest.ResolvedFindings = previousRun.Findings
                .Where(f => f.Severity is "Critical" or "Warning")
                .Where(f => !currentTitles.Contains(f.Title))
                .Select(f => f.Title)
                .Distinct()
                .Take(5)
                .ToList();
        }

        return digest;
    }

    /// <summary>
    /// Compute a health pulse rating based on score, trend, and critical count.
    /// </summary>
    public static DigestPulse ComputePulse(SecurityDigest digest)
    {
        if (digest.CriticalCount >= 5 || digest.CurrentScore < 30)
            return DigestPulse.Critical;
        if (digest.CriticalCount >= 2 || digest.CurrentScore < 50)
            return DigestPulse.Unhealthy;
        if (digest.CriticalCount >= 1 || digest.CurrentScore < 70 ||
            digest.Trend == DigestTrend.Declining)
            return DigestPulse.NeedsAttention;
        if (digest.CurrentScore >= 90 && digest.Trend != DigestTrend.Declining)
            return DigestPulse.Excellent;
        return DigestPulse.Healthy;
    }

    /// <summary>
    /// Render the digest as plain text.
    /// </summary>
    public static string RenderText(SecurityDigest digest)
    {
        var sb = new StringBuilder();
        var divider = new string('─', 50);

        sb.AppendLine(divider);
        sb.AppendLine($"  🛡️  WinSentinel Security Digest");
        sb.AppendLine($"  {digest.MachineName} | {digest.GeneratedAt:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine(divider);
        sb.AppendLine();

        // Pulse
        var pulseEmoji = digest.Pulse switch
        {
            DigestPulse.Excellent => "💚",
            DigestPulse.Healthy => "🟢",
            DigestPulse.NeedsAttention => "🟡",
            DigestPulse.Unhealthy => "🟠",
            DigestPulse.Critical => "🔴",
            _ => "⚪"
        };
        sb.AppendLine($"  Health: {pulseEmoji} {digest.Pulse}");
        sb.AppendLine();

        // Score with trend arrow
        var trendArrow = digest.Trend switch
        {
            DigestTrend.Improving => "↑",
            DigestTrend.Declining => "↓",
            DigestTrend.Stable => "→",
            _ => ""
        };
        var deltaStr = digest.ScoreDelta.HasValue && digest.ScoreDelta.Value != 0
            ? $" ({(digest.ScoreDelta.Value > 0 ? "+" : "")}{digest.ScoreDelta.Value})"
            : "";
        sb.AppendLine($"  Score: {digest.CurrentScore}/100 ({digest.CurrentGrade}) {trendArrow}{deltaStr}");

        if (digest.PreviousScore.HasValue)
        {
            sb.AppendLine($"  Previous: {digest.PreviousScore}/100 ({digest.PreviousGrade})");
        }
        sb.AppendLine();

        // Sparkline
        if (digest.ScoreHistory.Count > 1)
        {
            sb.AppendLine($"  Trend: {RenderSparkline(digest.ScoreHistory)}");
            sb.AppendLine();
        }

        // Findings summary
        sb.AppendLine($"  Findings: {digest.TotalFindings} total");
        sb.AppendLine($"    🔴 Critical: {digest.CriticalCount}" +
                      (digest.CriticalDelta.HasValue && digest.CriticalDelta.Value != 0
                          ? $" ({(digest.CriticalDelta.Value > 0 ? "+" : "")}{digest.CriticalDelta.Value})"
                          : ""));
        sb.AppendLine($"    🟡 Warning:  {digest.WarningCount}" +
                      (digest.WarningDelta.HasValue && digest.WarningDelta.Value != 0
                          ? $" ({(digest.WarningDelta.Value > 0 ? "+" : "")}{digest.WarningDelta.Value})"
                          : ""));
        sb.AppendLine($"    ℹ️  Info:     {digest.InfoCount}");
        sb.AppendLine($"    ✅ Pass:     {digest.PassCount}");
        sb.AppendLine();

        // New / Resolved findings
        if (digest.NewFindings.Count > 0)
        {
            sb.AppendLine("  🆕 New Issues:");
            foreach (var title in digest.NewFindings)
                sb.AppendLine($"    • {title}");
            sb.AppendLine();
        }

        if (digest.ResolvedFindings.Count > 0)
        {
            sb.AppendLine("  ✅ Resolved:");
            foreach (var title in digest.ResolvedFindings)
                sb.AppendLine($"    • {title}");
            sb.AppendLine();
        }

        // Top risks
        if (digest.TopRisks.Count > 0)
        {
            sb.AppendLine("  ⚠️  Top Risks:");
            foreach (var risk in digest.TopRisks)
            {
                var sevIcon = risk.Severity == Severity.Critical ? "🔴" : "🟡";
                var fixTag = risk.HasAutoFix ? " [auto-fixable]" : "";
                sb.AppendLine($"    {sevIcon} {risk.Title}{fixTag}");
                sb.AppendLine($"       Category: {risk.Category}");
            }
            sb.AppendLine();
        }

        // Module breakdown
        if (digest.ModuleBreakdown.Count > 0)
        {
            sb.AppendLine("  📊 Module Scores:");
            foreach (var mod in digest.ModuleBreakdown)
            {
                var bar = RenderBar(mod.Score, 15);
                sb.AppendLine($"    {mod.Score,3}/100 {bar} {mod.ModuleName}");
            }
            sb.AppendLine();
        }

        // Actions
        sb.AppendLine($"  🔧 Actions:");
        sb.AppendLine($"    Auto-fixable: {digest.AutoFixableCount} (run 'winsentinel fix-all')");
        sb.AppendLine($"    Manual:       {digest.ManualActionCount}");
        sb.AppendLine();

        // Scan info
        sb.AppendLine($"  Modules scanned: {digest.ModulesScanned} | Duration: {digest.ScanDuration.TotalSeconds:F1}s");
        sb.AppendLine(divider);

        return sb.ToString();
    }

    /// <summary>
    /// Render the digest as self-contained HTML.
    /// </summary>
    public static string RenderHtml(SecurityDigest digest)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine($"<title>WinSentinel Digest — {HtmlEncode(digest.MachineName)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(HtmlStyles);
        sb.AppendLine("</style></head><body>");
        sb.AppendLine("<div class=\"digest\">");

        // Header
        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine("<h1>🛡️ WinSentinel Security Digest</h1>");
        sb.AppendLine($"<p class=\"meta\">{HtmlEncode(digest.MachineName)} &middot; {digest.GeneratedAt:yyyy-MM-dd HH:mm} UTC</p>");
        sb.AppendLine("</div>");

        // Pulse banner
        var (pulseClass, pulseLabel) = digest.Pulse switch
        {
            DigestPulse.Excellent => ("pulse-excellent", "💚 Excellent"),
            DigestPulse.Healthy => ("pulse-healthy", "🟢 Healthy"),
            DigestPulse.NeedsAttention => ("pulse-attention", "🟡 Needs Attention"),
            DigestPulse.Unhealthy => ("pulse-unhealthy", "🟠 Unhealthy"),
            DigestPulse.Critical => ("pulse-critical", "🔴 Critical"),
            _ => ("pulse-healthy", "⚪ Unknown")
        };
        sb.AppendLine($"<div class=\"pulse {pulseClass}\">{pulseLabel}</div>");

        // Score card
        sb.AppendLine("<div class=\"score-card\">");
        var trendArrow = digest.Trend switch
        {
            DigestTrend.Improving => "<span class=\"trend-up\">↑</span>",
            DigestTrend.Declining => "<span class=\"trend-down\">↓</span>",
            DigestTrend.Stable => "<span class=\"trend-stable\">→</span>",
            _ => ""
        };
        sb.AppendLine($"<div class=\"score-big\">{digest.CurrentScore}<span class=\"score-max\">/100</span></div>");
        sb.AppendLine($"<div class=\"grade\">{HtmlEncode(digest.CurrentGrade)} {trendArrow}</div>");
        if (digest.ScoreDelta.HasValue && digest.ScoreDelta.Value != 0)
        {
            var deltaClass = digest.ScoreDelta.Value > 0 ? "delta-positive" : "delta-negative";
            sb.AppendLine($"<div class=\"{deltaClass}\">{(digest.ScoreDelta.Value > 0 ? "+" : "")}{digest.ScoreDelta.Value} from last scan</div>");
        }
        sb.AppendLine("</div>");

        // Findings summary grid
        sb.AppendLine("<div class=\"findings-grid\">");
        sb.AppendLine($"<div class=\"stat critical\"><span class=\"stat-num\">{digest.CriticalCount}</span><span class=\"stat-label\">Critical</span></div>");
        sb.AppendLine($"<div class=\"stat warning\"><span class=\"stat-num\">{digest.WarningCount}</span><span class=\"stat-label\">Warning</span></div>");
        sb.AppendLine($"<div class=\"stat info\"><span class=\"stat-num\">{digest.InfoCount}</span><span class=\"stat-label\">Info</span></div>");
        sb.AppendLine($"<div class=\"stat pass\"><span class=\"stat-num\">{digest.PassCount}</span><span class=\"stat-label\">Pass</span></div>");
        sb.AppendLine("</div>");

        // New / Resolved
        if (digest.NewFindings.Count > 0 || digest.ResolvedFindings.Count > 0)
        {
            sb.AppendLine("<div class=\"changes\">");
            if (digest.NewFindings.Count > 0)
            {
                sb.AppendLine("<div class=\"change-section\"><h3>🆕 New Issues</h3><ul>");
                foreach (var t in digest.NewFindings)
                    sb.AppendLine($"<li>{HtmlEncode(t)}</li>");
                sb.AppendLine("</ul></div>");
            }
            if (digest.ResolvedFindings.Count > 0)
            {
                sb.AppendLine("<div class=\"change-section resolved\"><h3>✅ Resolved</h3><ul>");
                foreach (var t in digest.ResolvedFindings)
                    sb.AppendLine($"<li>{HtmlEncode(t)}</li>");
                sb.AppendLine("</ul></div>");
            }
            sb.AppendLine("</div>");
        }

        // Top risks
        if (digest.TopRisks.Count > 0)
        {
            sb.AppendLine("<h2>⚠️ Top Risks</h2>");
            sb.AppendLine("<table class=\"risks\"><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Fix</th></tr></thead><tbody>");
            foreach (var risk in digest.TopRisks)
            {
                var sevBadge = risk.Severity == Severity.Critical
                    ? "<span class=\"badge-critical\">Critical</span>"
                    : "<span class=\"badge-warning\">Warning</span>";
                var fixBadge = risk.HasAutoFix
                    ? "<span class=\"badge-auto\">Auto</span>"
                    : "<span class=\"badge-manual\">Manual</span>";
                sb.AppendLine($"<tr><td>{sevBadge}</td><td>{HtmlEncode(risk.Title)}</td><td>{HtmlEncode(risk.Category)}</td><td>{fixBadge}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
        }

        // Module breakdown
        if (digest.ModuleBreakdown.Count > 0)
        {
            sb.AppendLine("<h2>📊 Module Scores</h2>");
            sb.AppendLine("<table class=\"modules\"><thead><tr><th>Module</th><th>Score</th><th>Status</th></tr></thead><tbody>");
            foreach (var mod in digest.ModuleBreakdown)
            {
                var barWidth = mod.Score;
                var barColor = mod.Score >= 80 ? "#22c55e" : mod.Score >= 50 ? "#eab308" : "#ef4444";
                sb.AppendLine($"<tr><td>{HtmlEncode(mod.ModuleName)}</td><td><div class=\"bar-container\"><div class=\"bar\" style=\"width:{barWidth}%;background:{barColor}\"></div><span class=\"bar-label\">{mod.Score}</span></div></td><td>{mod.Status}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
        }

        // Actions
        sb.AppendLine("<div class=\"actions\">");
        sb.AppendLine($"<div class=\"action-item\">🔧 <strong>{digest.AutoFixableCount}</strong> auto-fixable — run <code>winsentinel fix-all</code></div>");
        sb.AppendLine($"<div class=\"action-item\">🔨 <strong>{digest.ManualActionCount}</strong> require manual attention</div>");
        sb.AppendLine("</div>");

        // Footer
        sb.AppendLine($"<div class=\"footer\">{digest.ModulesScanned} modules scanned in {digest.ScanDuration.TotalSeconds:F1}s</div>");
        sb.AppendLine("</div></body></html>");

        return sb.ToString();
    }

    /// <summary>
    /// Render the digest as JSON.
    /// </summary>
    public static string RenderJson(SecurityDigest digest)
    {
        return JsonSerializer.Serialize(digest, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
    }

    private static string RenderSparkline(List<int> scores)
    {
        var blocks = "▁▂▃▄▅▆▇█";
        var min = scores.Min();
        var max = scores.Max();
        var range = max - min;
        if (range == 0) return new string(blocks[4], scores.Count);

        return new string(scores.Select(s =>
        {
            var idx = (int)((double)(s - min) / range * (blocks.Length - 1));
            return blocks[idx];
        }).ToArray());
    }

    private static string RenderBar(int score, int width)
    {
        var filled = (int)Math.Round(score / 100.0 * width);
        return new string('█', filled) + new string('░', width - filled);
    }

    private static string HtmlEncode(string text) =>
        System.Net.WebUtility.HtmlEncode(text);

    private const string HtmlStyles = @"
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }
.digest { max-width: 640px; margin: 24px auto; background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
.header { padding: 24px; border-bottom: 1px solid #e2e8f0; }
.header h1 { font-size: 20px; }
.meta { color: #64748b; font-size: 13px; margin-top: 4px; }
.pulse { padding: 12px 24px; font-size: 16px; font-weight: 600; text-align: center; }
.pulse-excellent { background: #dcfce7; color: #166534; }
.pulse-healthy { background: #dcfce7; color: #166534; }
.pulse-attention { background: #fef9c3; color: #854d0e; }
.pulse-unhealthy { background: #fed7aa; color: #9a3412; }
.pulse-critical { background: #fecaca; color: #991b1b; }
.score-card { padding: 24px; text-align: center; }
.score-big { font-size: 48px; font-weight: 700; }
.score-max { font-size: 20px; color: #94a3b8; }
.grade { font-size: 24px; font-weight: 600; margin-top: 4px; }
.trend-up { color: #22c55e; }
.trend-down { color: #ef4444; }
.trend-stable { color: #64748b; }
.delta-positive { color: #22c55e; font-size: 14px; }
.delta-negative { color: #ef4444; font-size: 14px; }
.findings-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; }
.stat { padding: 16px; text-align: center; }
.stat-num { display: block; font-size: 28px; font-weight: 700; }
.stat-label { font-size: 12px; color: #64748b; text-transform: uppercase; }
.stat.critical .stat-num { color: #ef4444; }
.stat.warning .stat-num { color: #eab308; }
.stat.info .stat-num { color: #3b82f6; }
.stat.pass .stat-num { color: #22c55e; }
.changes { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px 24px; }
.change-section h3 { font-size: 14px; margin-bottom: 8px; }
.change-section ul { list-style: none; font-size: 13px; }
.change-section ul li { padding: 2px 0; }
.change-section ul li::before { content: '• '; color: #ef4444; }
.change-section.resolved ul li::before { color: #22c55e; }
h2 { padding: 16px 24px 8px; font-size: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 24px; background: #f8fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0; }
td { padding: 8px 24px; border-bottom: 1px solid #f1f5f9; }
.badge-critical { background: #fecaca; color: #991b1b; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-warning { background: #fef3c7; color: #92400e; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-auto { background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
.badge-manual { background: #e2e8f0; color: #475569; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
.bar-container { display: flex; align-items: center; gap: 8px; }
.bar { height: 8px; border-radius: 4px; min-width: 4px; }
.bar-label { font-size: 12px; font-weight: 600; }
.actions { padding: 16px 24px; border-top: 1px solid #e2e8f0; }
.action-item { padding: 4px 0; font-size: 14px; }
code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
.footer { padding: 12px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
";
}

/// <summary>
/// A concise security digest with metrics, trends, and action items.
/// </summary>
public class SecurityDigest
{
    public DateTimeOffset GeneratedAt { get; set; }
    public string MachineName { get; set; } = "";

    // Score
    public int CurrentScore { get; set; }
    public string CurrentGrade { get; set; } = "";
    public int? PreviousScore { get; set; }
    public string? PreviousGrade { get; set; }
    public int? ScoreDelta { get; set; }

    // Findings
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
    public int PassCount { get; set; }
    public int? CriticalDelta { get; set; }
    public int? WarningDelta { get; set; }

    // Trend
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public DigestTrend Trend { get; set; } = DigestTrend.Unknown;

    // Pulse
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public DigestPulse Pulse { get; set; } = DigestPulse.Healthy;

    // Details
    public List<DigestRiskItem> TopRisks { get; set; } = [];
    public List<DigestModuleEntry> ModuleBreakdown { get; set; } = [];
    public List<int> ScoreHistory { get; set; } = [];
    public List<string> NewFindings { get; set; } = [];
    public List<string> ResolvedFindings { get; set; } = [];

    // Modules
    public string? WeakestModule { get; set; }
    public string? StrongestModule { get; set; }
    public int ModulesScanned { get; set; }
    public TimeSpan ScanDuration { get; set; }

    // Actions
    public int AutoFixableCount { get; set; }
    public int ManualActionCount { get; set; }
}

public class DigestRiskItem
{
    public string Title { get; set; } = "";
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity Severity { get; set; }
    public string Category { get; set; } = "";
    public bool HasAutoFix { get; set; }
    public string? Remediation { get; set; }
}

public class DigestModuleEntry
{
    public string ModuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public string Status { get; set; } = "";
}

public enum DigestTrend
{
    Unknown,
    Improving,
    Stable,
    Declining
}

public enum DigestPulse
{
    Excellent,
    Healthy,
    NeedsAttention,
    Unhealthy,
    Critical
}
