using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates shields.io-style SVG badges for security audit results.
/// Badges can be embedded in README files, dashboards, or CI/CD pipelines.
/// </summary>
public class BadgeGenerator
{
    /// <summary>
    /// Badge style variants matching shields.io conventions.
    /// </summary>
    public enum BadgeStyle
    {
        /// <summary>Default flat style with gradient.</summary>
        Flat,
        /// <summary>Flat style without gradient.</summary>
        FlatSquare,
        /// <summary>Rounded "pill" style for larger badges.</summary>
        ForTheBadge
    }

    /// <summary>
    /// Generate a security score badge showing the overall score and grade.
    /// Example: [WinSentinel | 85/100 A]
    /// </summary>
    public string GenerateScoreBadge(SecurityReport report, BadgeStyle style = BadgeStyle.Flat)
    {
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);
        var color = GetBadgeColor(score);

        return style switch
        {
            BadgeStyle.FlatSquare => GenerateFlatSquareSvg("WinSentinel", $"{score}/100 {grade}", color),
            BadgeStyle.ForTheBadge => GenerateForTheBadgeSvg("WINSENTINEL", $"{score}/100 {grade}", color),
            _ => GenerateFlatSvg("WinSentinel", $"{score}/100 {grade}", color)
        };
    }

    /// <summary>
    /// Generate a grade-only badge.
    /// Example: [security | A]
    /// </summary>
    public string GenerateGradeBadge(SecurityReport report, BadgeStyle style = BadgeStyle.Flat)
    {
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);
        var color = GetBadgeColor(score);

        return style switch
        {
            BadgeStyle.FlatSquare => GenerateFlatSquareSvg("security", $"grade {grade}", color),
            BadgeStyle.ForTheBadge => GenerateForTheBadgeSvg("SECURITY", $"GRADE {grade}", color),
            _ => GenerateFlatSvg("security", $"grade {grade}", color)
        };
    }

    /// <summary>
    /// Generate a findings summary badge.
    /// Example: [findings | 2 critical · 5 warnings]
    /// </summary>
    public string GenerateFindingsBadge(SecurityReport report, BadgeStyle style = BadgeStyle.Flat)
    {
        var parts = new List<string>();
        if (report.TotalCritical > 0)
            parts.Add($"{report.TotalCritical} critical");
        if (report.TotalWarnings > 0)
            parts.Add($"{report.TotalWarnings} warnings");
        if (parts.Count == 0)
            parts.Add("all clear");

        var message = string.Join(" \u00b7 ", parts);
        var color = report.TotalCritical > 0 ? "#e05d44" : report.TotalWarnings > 0 ? "#dfb317" : "#4c1";

        return style switch
        {
            BadgeStyle.FlatSquare => GenerateFlatSquareSvg("findings", message, color),
            BadgeStyle.ForTheBadge => GenerateForTheBadgeSvg("FINDINGS", message.ToUpperInvariant(), color),
            _ => GenerateFlatSvg("findings", message, color)
        };
    }

    /// <summary>
    /// Generate a badge for a specific audit module.
    /// Example: [firewall | 100 A]
    /// </summary>
    public string GenerateModuleBadge(AuditResult result, BadgeStyle style = BadgeStyle.Flat)
    {
        var score = SecurityScorer.CalculateCategoryScore(result);
        var grade = SecurityScorer.GetGrade(score);
        var color = GetBadgeColor(score);
        var label = result.Category.ToLowerInvariant();

        return style switch
        {
            BadgeStyle.FlatSquare => GenerateFlatSquareSvg(label, $"{score} {grade}", color),
            BadgeStyle.ForTheBadge => GenerateForTheBadgeSvg(label.ToUpperInvariant(), $"{score} {grade}", color),
            _ => GenerateFlatSvg(label, $"{score} {grade}", color)
        };
    }

    /// <summary>
    /// Generate all module badges as a combined SVG (vertical stack).
    /// </summary>
    public string GenerateAllModuleBadges(SecurityReport report, BadgeStyle style = BadgeStyle.Flat)
    {
        if (report.Results.Count == 0) return GenerateFlatSvg("modules", "none", "#9f9f9f");

        var badges = report.Results
            .OrderByDescending(r => SecurityScorer.CalculateCategoryScore(r))
            .Select(r => GenerateModuleBadge(r, style))
            .ToList();

        // Stack vertically with 4px gaps
        const int badgeHeight = 20;
        const int gap = 4;
        var totalHeight = badges.Count * badgeHeight + (badges.Count - 1) * gap;

        var sb = new StringBuilder();
        sb.AppendLine($"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"220\" height=\"{totalHeight}\">");

        for (int i = 0; i < badges.Count; i++)
        {
            var y = i * (badgeHeight + gap);
            // Extract the inner SVG content and wrap in a translated group
            var inner = badges[i]
                .Replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "")
                .Replace("<svg xmlns=\"http://www.w3.org/2000/svg\"", $"<svg y=\"{y}\"");
            sb.Append(inner);
        }

        sb.AppendLine("</svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Save a badge SVG to a file.
    /// </summary>
    public void SaveBadge(string filePath, string svgContent)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(filePath, svgContent, new UTF8Encoding(false));
    }

    /// <summary>
    /// Generate a Markdown image reference for embedding a badge.
    /// </summary>
    public static string GetMarkdownEmbed(string badgeUrl, string altText = "WinSentinel Security Score", string? linkUrl = null)
    {
        if (string.IsNullOrEmpty(badgeUrl))
            throw new ArgumentException("Badge URL is required.", nameof(badgeUrl));

        var img = $"![{altText}]({badgeUrl})";
        return linkUrl != null ? $"[{img}]({linkUrl})" : img;
    }

    // ── SVG Generation ──────────────────────────────────────────────

    /// <summary>
    /// Generate a flat badge SVG with gradient (shields.io default style).
    /// </summary>
    public string GenerateFlatSvg(string label, string message, string color)
    {
        var labelWidth = EstimateTextWidth(label, 11) + 10;
        var messageWidth = EstimateTextWidth(message, 11) + 10;
        var totalWidth = labelWidth + messageWidth;

        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.Append($"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{totalWidth}\" height=\"20\">");

        // Gradient definition
        sb.Append("<linearGradient id=\"s\" x2=\"0\" y2=\"100%\">");
        sb.Append("<stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>");
        sb.Append("<stop offset=\"1\" stop-opacity=\".1\"/>");
        sb.Append("</linearGradient>");

        // Clip path for rounded corners
        sb.Append($"<clipPath id=\"r\"><rect width=\"{totalWidth}\" height=\"20\" rx=\"3\" fill=\"#fff\"/></clipPath>");
        sb.Append("<g clip-path=\"url(#r)\">");

        // Label background (dark gray)
        sb.Append($"<rect width=\"{labelWidth}\" height=\"20\" fill=\"#555\"/>");
        // Message background (colored)
        sb.Append($"<rect x=\"{labelWidth}\" width=\"{messageWidth}\" height=\"20\" fill=\"{SvgEscape(color)}\"/>");
        // Gradient overlay
        sb.Append($"<rect width=\"{totalWidth}\" height=\"20\" fill=\"url(#s)\"/>");

        sb.Append("</g>");

        // Text shadows + text
        sb.Append("<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" font-size=\"11\">");
        sb.Append($"<text x=\"{labelWidth / 2.0:F1}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{SvgEscape(label)}</text>");
        sb.Append($"<text x=\"{labelWidth / 2.0:F1}\" y=\"14\">{SvgEscape(label)}</text>");
        sb.Append($"<text x=\"{labelWidth + messageWidth / 2.0:F1}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{SvgEscape(message)}</text>");
        sb.Append($"<text x=\"{labelWidth + messageWidth / 2.0:F1}\" y=\"14\">{SvgEscape(message)}</text>");
        sb.Append("</g>");

        sb.Append("</svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Generate a flat-square badge SVG (no gradient, sharp corners).
    /// </summary>
    public string GenerateFlatSquareSvg(string label, string message, string color)
    {
        var labelWidth = EstimateTextWidth(label, 11) + 10;
        var messageWidth = EstimateTextWidth(message, 11) + 10;
        var totalWidth = labelWidth + messageWidth;

        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.Append($"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{totalWidth}\" height=\"20\">");

        // No rounded corners, no gradient
        sb.Append($"<rect width=\"{labelWidth}\" height=\"20\" fill=\"#555\"/>");
        sb.Append($"<rect x=\"{labelWidth}\" width=\"{messageWidth}\" height=\"20\" fill=\"{SvgEscape(color)}\"/>");

        // Text
        sb.Append("<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" font-size=\"11\">");
        sb.Append($"<text x=\"{labelWidth / 2.0:F1}\" y=\"14\">{SvgEscape(label)}</text>");
        sb.Append($"<text x=\"{labelWidth + messageWidth / 2.0:F1}\" y=\"14\">{SvgEscape(message)}</text>");
        sb.Append("</g>");

        sb.Append("</svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Generate a "for-the-badge" style SVG (larger, uppercase, wider padding).
    /// </summary>
    public string GenerateForTheBadgeSvg(string label, string message, string color)
    {
        var labelWidth = EstimateTextWidth(label, 10, true) + 18;
        var messageWidth = EstimateTextWidth(message, 10, true) + 18;
        var totalWidth = labelWidth + messageWidth;
        const int height = 28;

        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.Append($"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{totalWidth}\" height=\"{height}\">");

        // Rounded rect clip
        sb.Append($"<clipPath id=\"r\"><rect width=\"{totalWidth}\" height=\"{height}\" rx=\"4\" fill=\"#fff\"/></clipPath>");
        sb.Append("<g clip-path=\"url(#r)\">");

        sb.Append($"<rect width=\"{labelWidth}\" height=\"{height}\" fill=\"#555\"/>");
        sb.Append($"<rect x=\"{labelWidth}\" width=\"{messageWidth}\" height=\"{height}\" fill=\"{SvgEscape(color)}\"/>");

        sb.Append("</g>");

        // Bold uppercase text
        sb.Append("<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" font-size=\"10\" font-weight=\"bold\" letter-spacing=\"1\">");
        sb.Append($"<text x=\"{labelWidth / 2.0:F1}\" y=\"18\">{SvgEscape(label.ToUpperInvariant())}</text>");
        sb.Append($"<text x=\"{labelWidth + messageWidth / 2.0:F1}\" y=\"18\">{SvgEscape(message.ToUpperInvariant())}</text>");
        sb.Append("</g>");

        sb.Append("</svg>");
        return sb.ToString();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Estimate pixel width of text for badge layout.
    /// Uses average character widths for Verdana at common sizes.
    /// </summary>
    public static int EstimateTextWidth(string text, int fontSize, bool bold = false)
    {
        if (string.IsNullOrEmpty(text)) return 0;

        // Average character widths for Verdana at 11px (matching shields.io)
        double avgCharWidth = fontSize switch
        {
            10 => bold ? 7.0 : 6.2,
            11 => bold ? 7.5 : 6.7,
            _ => bold ? 7.5 : 6.7
        };

        // Narrower chars get less width, wider get more
        double width = 0;
        foreach (var ch in text)
        {
            width += ch switch
            {
                'i' or 'l' or '!' or '|' or '.' or ',' or ':' or ';' or '\'' => avgCharWidth * 0.5,
                'I' or '1' or ' ' => avgCharWidth * 0.6,
                'm' or 'M' or 'W' or 'w' => avgCharWidth * 1.3,
                _ when char.IsUpper(ch) => avgCharWidth * 1.1,
                _ => avgCharWidth
            };
        }

        return (int)Math.Ceiling(width);
    }

    /// <summary>
    /// Get badge color based on score (shields.io color scheme).
    /// </summary>
    public static string GetBadgeColor(int score) => score switch
    {
        >= 90 => "#4c1",       // bright green
        >= 80 => "#97ca00",    // green
        >= 70 => "#a4a61d",    // yellow-green
        >= 60 => "#dfb317",    // yellow
        >= 40 => "#fe7d37",    // orange
        _ => "#e05d44"         // red
    };

    /// <summary>
    /// Escape text for safe SVG embedding.
    /// </summary>
    public static string SvgEscape(string text)
    {
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;");
    }
}
