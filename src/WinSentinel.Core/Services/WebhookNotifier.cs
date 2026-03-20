using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Webhook delivery targets.
/// </summary>
public enum WebhookPlatform
{
    /// <summary>Auto-detect from URL.</summary>
    Auto,
    /// <summary>Generic JSON POST.</summary>
    Generic,
    /// <summary>Slack Incoming Webhook.</summary>
    Slack,
    /// <summary>Discord Webhook.</summary>
    Discord,
    /// <summary>Microsoft Teams Incoming Webhook.</summary>
    Teams
}

/// <summary>
/// Configuration for webhook delivery.
/// </summary>
public class WebhookConfig
{
    public required string Url { get; set; }
    public WebhookPlatform Platform { get; set; } = WebhookPlatform.Auto;
    public Severity MinSeverity { get; set; } = Severity.Warning;
    public bool IncludeFindings { get; set; } = true;
    public int MaxFindings { get; set; } = 25;
    public string? CustomTitle { get; set; }
}

/// <summary>
/// Result of a webhook delivery attempt.
/// </summary>
public class WebhookResult
{
    public bool Success { get; set; }
    public int StatusCode { get; set; }
    public string? Error { get; set; }
    public string Platform { get; set; } = "generic";
    public string PayloadPreview { get; set; } = "";
}

/// <summary>
/// Sends security audit results to webhook endpoints (Slack, Discord,
/// Teams, or generic JSON). Formats messages natively for each platform.
/// </summary>
public class WebhookNotifier
{
    private readonly HttpClient _httpClient;
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public WebhookNotifier(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
    }

    /// <summary>
    /// Sends audit results to the configured webhook URL.
    /// </summary>
    public async Task<WebhookResult> SendAsync(SecurityReport report, WebhookConfig config)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(config);

        if (string.IsNullOrWhiteSpace(config.Url))
            return new WebhookResult { Success = false, Error = "Webhook URL is required." };

        var platform = config.Platform == WebhookPlatform.Auto
            ? DetectPlatform(config.Url)
            : config.Platform;

        var payload = platform switch
        {
            WebhookPlatform.Slack => BuildSlackPayload(report, config),
            WebhookPlatform.Discord => BuildDiscordPayload(report, config),
            WebhookPlatform.Teams => BuildTeamsPayload(report, config),
            _ => BuildGenericPayload(report, config)
        };

        var json = JsonSerializer.Serialize(payload, _jsonOptions);
        var result = new WebhookResult
        {
            Platform = platform.ToString().ToLowerInvariant(),
            PayloadPreview = json.Length > 500 ? json[..500] + "..." : json
        };

        try
        {
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(config.Url, content);

            result.StatusCode = (int)response.StatusCode;
            result.Success = response.IsSuccessStatusCode;

            if (!response.IsSuccessStatusCode)
                result.Error = $"HTTP {result.StatusCode}: {await response.Content.ReadAsStringAsync()}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Builds a preview of what would be sent without actually sending.
    /// </summary>
    public string Preview(SecurityReport report, WebhookConfig config)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(config);

        var platform = config.Platform == WebhookPlatform.Auto
            ? DetectPlatform(config.Url)
            : config.Platform;

        var payload = platform switch
        {
            WebhookPlatform.Slack => BuildSlackPayload(report, config),
            WebhookPlatform.Discord => BuildDiscordPayload(report, config),
            WebhookPlatform.Teams => BuildTeamsPayload(report, config),
            _ => BuildGenericPayload(report, config)
        };

        return JsonSerializer.Serialize(payload, _jsonOptions);
    }

    // ── Platform Detection ───────────────────────────────────────────

    public static WebhookPlatform DetectPlatform(string url)
    {
        var lower = url.ToLowerInvariant();

        if (lower.Contains("hooks.slack.com"))
            return WebhookPlatform.Slack;
        if (lower.Contains("discord.com/api/webhooks") || lower.Contains("discordapp.com/api/webhooks"))
            return WebhookPlatform.Discord;
        if (lower.Contains("webhook.office.com") || lower.Contains("outlook.office.com"))
            return WebhookPlatform.Teams;

        return WebhookPlatform.Generic;
    }

    // ── Finding Helpers ──────────────────────────────────────────────

    private static List<Finding> FilterFindings(SecurityReport report, WebhookConfig config)
    {
        return report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= config.MinSeverity)
            .OrderByDescending(f => f.Severity)
            .Take(config.MaxFindings)
            .ToList();
    }

    private static string ScoreEmoji(int score) => score switch
    {
        >= 90 => "🟢",
        >= 70 => "🟡",
        >= 50 => "🟠",
        _ => "🔴"
    };

    private static string ScoreGrade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };

    private static string SeverityEmoji(Severity severity) => severity switch
    {
        Severity.Critical => "🔴",
        Severity.Warning => "🟡",
        Severity.Info => "🔵",
        Severity.Pass => "✅",
        _ => "⚪"
    };

    private static string Hostname()
    {
        try { return Environment.MachineName; }
        catch { return "unknown"; }
    }

    // ── Generic JSON ─────────────────────────────────────────────────

    private static object BuildGenericPayload(SecurityReport report, WebhookConfig config)
    {
        var findings = FilterFindings(report, config);
        return new
        {
            title = config.CustomTitle ?? $"WinSentinel Security Report — {Hostname()}",
            timestamp = report.GeneratedAt.ToString("o"),
            score = report.SecurityScore,
            grade = ScoreGrade(report.SecurityScore),
            summary = new
            {
                total = report.TotalFindings,
                critical = report.TotalCritical,
                warnings = report.TotalWarnings,
                info = report.TotalInfo,
                pass = report.TotalPass
            },
            findings = config.IncludeFindings
                ? findings.Select(f => new
                {
                    title = f.Title,
                    severity = f.Severity.ToString(),
                    description = f.Description,
                    remediation = f.Remediation
                }).ToList()
                : null,
            hostname = Hostname()
        };
    }

    // ── Slack ────────────────────────────────────────────────────────

    private static object BuildSlackPayload(SecurityReport report, WebhookConfig config)
    {
        var title = config.CustomTitle ?? $"WinSentinel — {Hostname()}";
        var findings = FilterFindings(report, config);

        var blocks = new List<object>
        {
            new { type = "header", text = new { type = "plain_text", text = title } },
            new
            {
                type = "section",
                fields = new object[]
                {
                    new { type = "mrkdwn", text = $"*Score:* {ScoreEmoji(report.SecurityScore)} *{report.SecurityScore}/100* ({ScoreGrade(report.SecurityScore)})" },
                    new { type = "mrkdwn", text = $"*Time:* {report.GeneratedAt:yyyy-MM-dd HH:mm}" },
                    new { type = "mrkdwn", text = $"*Critical:* {report.TotalCritical}  |  *Warnings:* {report.TotalWarnings}" },
                    new { type = "mrkdwn", text = $"*Info:* {report.TotalInfo}  |  *Pass:* {report.TotalPass}" }
                }
            }
        };

        if (config.IncludeFindings && findings.Count > 0)
        {
            blocks.Add(new { type = "divider" });
            blocks.Add(new
            {
                type = "section",
                text = new { type = "mrkdwn", text = $"*Top Findings ({findings.Count}):*" }
            });

            foreach (var f in findings.Take(10))
            {
                blocks.Add(new
                {
                    type = "section",
                    text = new
                    {
                        type = "mrkdwn",
                        text = $"{SeverityEmoji(f.Severity)} *{f.Title}*\n{Truncate(f.Description, 200)}"
                    }
                });
            }
        }

        return new { blocks };
    }

    // ── Discord ──────────────────────────────────────────────────────

    private static object BuildDiscordPayload(SecurityReport report, WebhookConfig config)
    {
        var title = config.CustomTitle ?? $"WinSentinel — {Hostname()}";
        var findings = FilterFindings(report, config);

        var color = report.SecurityScore switch
        {
            >= 90 => 0x2ECC71, // green
            >= 70 => 0xF1C40F, // yellow
            >= 50 => 0xE67E22, // orange
            _ => 0xE74C3C     // red
        };

        var fields = new List<object>
        {
            new { name = "Score", value = $"{ScoreEmoji(report.SecurityScore)} **{report.SecurityScore}/100** ({ScoreGrade(report.SecurityScore)})", inline = true },
            new { name = "Critical", value = report.TotalCritical.ToString(), inline = true },
            new { name = "Warnings", value = report.TotalWarnings.ToString(), inline = true }
        };

        if (config.IncludeFindings && findings.Count > 0)
        {
            var findingsText = string.Join("\n", findings.Take(10)
                .Select(f => $"{SeverityEmoji(f.Severity)} **{f.Title}** — {Truncate(f.Description, 100)}"));
            fields.Add(new { name = $"Top Findings ({findings.Count})", value = findingsText, inline = false });
        }

        return new
        {
            embeds = new[]
            {
                new
                {
                    title,
                    color,
                    fields,
                    timestamp = report.GeneratedAt.ToString("o"),
                    footer = new { text = $"Host: {Hostname()}" }
                }
            }
        };
    }

    // ── Teams ────────────────────────────────────────────────────────

    private static object BuildTeamsPayload(SecurityReport report, WebhookConfig config)
    {
        var title = config.CustomTitle ?? $"WinSentinel — {Hostname()}";
        var findings = FilterFindings(report, config);

        var factsCore = new List<object>
        {
            new { name = "Score", value = $"{ScoreEmoji(report.SecurityScore)} {report.SecurityScore}/100 ({ScoreGrade(report.SecurityScore)})" },
            new { name = "Critical", value = report.TotalCritical.ToString() },
            new { name = "Warnings", value = report.TotalWarnings.ToString() },
            new { name = "Info", value = report.TotalInfo.ToString() },
            new { name = "Pass", value = report.TotalPass.ToString() },
            new { name = "Time", value = report.GeneratedAt.ToString("yyyy-MM-dd HH:mm") }
        };

        var sections = new List<object>
        {
            new
            {
                activityTitle = title,
                facts = factsCore,
                markdown = true
            }
        };

        if (config.IncludeFindings && findings.Count > 0)
        {
            var findingFacts = findings.Take(10)
                .Select(f => new
                {
                    name = $"{SeverityEmoji(f.Severity)} {f.Severity}",
                    value = $"**{f.Title}** — {Truncate(f.Description, 150)}"
                })
                .ToList<object>();

            sections.Add(new
            {
                activityTitle = $"Top Findings ({findings.Count})",
                facts = findingFacts,
                markdown = true
            });
        }

        return new
        {
            @themeColor = report.SecurityScore >= 70 ? "00CC00" : "CC0000",
            summary = $"Security Score: {report.SecurityScore}/100",
            sections
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static string Truncate(string? text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[..(max - 3)] + "...";
    }
}
