using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Sends scan results and alerts to external webhooks (Slack, Discord, Teams, or generic HTTP).
/// Supports multiple webhook endpoints with per-endpoint filtering by minimum severity
/// and score threshold. Auto-detects platform from URL and formats payloads accordingly.
/// </summary>
public class WebhookNotificationService
{
    private readonly HttpClient _httpClient;
    private readonly WebhookSettings _settings;

    public WebhookNotificationService(WebhookSettings settings, HttpClient? httpClient = null)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>
    /// Send scan results to all configured webhook endpoints that match the filter criteria.
    /// </summary>
    public async Task<List<WebhookDeliveryResult>> NotifyAsync(SecurityReport report, SecurityReport? previous = null)
    {
        var results = new List<WebhookDeliveryResult>();

        foreach (var endpoint in _settings.Endpoints)
        {
            if (!endpoint.Enabled) continue;
            if (!ShouldNotify(endpoint, report)) continue;

            try
            {
                var payload = BuildPayload(endpoint, report, previous);
                var content = new StringContent(payload, Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Url) { Content = content };
                if (!string.IsNullOrEmpty(endpoint.AuthorizationHeader))
                    request.Headers.TryAddWithoutValidation("Authorization", endpoint.AuthorizationHeader);

                var response = await _httpClient.SendAsync(request);

                results.Add(new WebhookDeliveryResult
                {
                    EndpointName = endpoint.Name,
                    Success = response.IsSuccessStatusCode,
                    StatusCode = (int)response.StatusCode,
                    Error = response.IsSuccessStatusCode ? null : await response.Content.ReadAsStringAsync()
                });
            }
            catch (Exception ex)
            {
                results.Add(new WebhookDeliveryResult
                {
                    EndpointName = endpoint.Name,
                    Success = false,
                    StatusCode = 0,
                    Error = ex.Message
                });
            }
        }

        return results;
    }

    /// <summary>
    /// Test connectivity to a specific endpoint by sending a test payload.
    /// </summary>
    public async Task<WebhookDeliveryResult> TestAsync(WebhookEndpoint endpoint)
    {
        var testReport = new SecurityReport
        {
            SecurityScore = 85,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "TestModule",
                    Category = "Test",
                    Findings = new List<Finding>
                    {
                        new() { Title = "Test Finding", Severity = Severity.Info, Description = "This is a test webhook delivery from WinSentinel." }
                    }
                }
            }
        };

        try
        {
            var payload = BuildPayload(endpoint, testReport, null);
            var content = new StringContent(payload, Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Url) { Content = content };
            if (!string.IsNullOrEmpty(endpoint.AuthorizationHeader))
                request.Headers.TryAddWithoutValidation("Authorization", endpoint.AuthorizationHeader);

            var response = await _httpClient.SendAsync(request);

            return new WebhookDeliveryResult
            {
                EndpointName = endpoint.Name,
                Success = response.IsSuccessStatusCode,
                StatusCode = (int)response.StatusCode,
                Error = response.IsSuccessStatusCode ? null : await response.Content.ReadAsStringAsync()
            };
        }
        catch (Exception ex)
        {
            return new WebhookDeliveryResult
            {
                EndpointName = endpoint.Name,
                Success = false,
                Error = ex.Message
            };
        }
    }

    public bool ShouldNotify(WebhookEndpoint endpoint, SecurityReport report)
    {
        if (endpoint.ScoreThreshold.HasValue && report.SecurityScore > endpoint.ScoreThreshold.Value)
            return false;

        if (endpoint.MinimumSeverity.HasValue)
        {
            var minSev = endpoint.MinimumSeverity.Value;
            bool hasMatch = minSev switch
            {
                Severity.Critical => report.TotalCritical > 0,
                Severity.Warning => report.TotalCritical > 0 || report.TotalWarnings > 0,
                _ => true
            };
            if (!hasMatch) return false;
        }

        return true;
    }

    public string BuildPayload(WebhookEndpoint endpoint, SecurityReport report, SecurityReport? previous)
    {
        var platform = endpoint.Platform ?? DetectPlatform(endpoint.Url);

        return platform switch
        {
            WebhookPlatform.Slack => BuildSlackPayload(report, previous),
            WebhookPlatform.Discord => BuildDiscordPayload(report, previous),
            WebhookPlatform.Teams => BuildTeamsPayload(report, previous),
            _ => BuildGenericPayload(report, previous)
        };
    }

    public static WebhookPlatform DetectPlatform(string url)
    {
        if (url.Contains("hooks.slack.com", StringComparison.OrdinalIgnoreCase))
            return WebhookPlatform.Slack;
        if (url.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) ||
            url.Contains("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase))
            return WebhookPlatform.Discord;
        if (url.Contains(".webhook.office.com", StringComparison.OrdinalIgnoreCase) ||
            url.Contains("microsoft.webhook", StringComparison.OrdinalIgnoreCase))
            return WebhookPlatform.Teams;

        return WebhookPlatform.Generic;
    }

    private static string GetGradeEmoji(int score) => score switch
    {
        >= 90 => "🟢",
        >= 70 => "🟡",
        >= 50 => "🟠",
        _ => "🔴"
    };

    private static string GetGrade(int score) => score switch
    {
        >= 95 => "A+", >= 90 => "A", >= 85 => "B+", >= 80 => "B",
        >= 75 => "C+", >= 70 => "C", >= 60 => "D", _ => "F"
    };

    private string BuildSlackPayload(SecurityReport report, SecurityReport? previous)
    {
        var emoji = GetGradeEmoji(report.SecurityScore);
        var grade = GetGrade(report.SecurityScore);
        var deltaText = FormatDelta(report, previous);

        var topFindings = GetTopFindings(report, 5);
        var findingsText = topFindings.Count > 0
            ? string.Join("\n", topFindings.Select(f =>
                $"• {(f.Severity == Severity.Critical ? "🔴" : "⚠️")} {f.Title}"))
            : "";

        var blocks = new List<object>
        {
            new { type = "header", text = new { type = "plain_text", text = $"{emoji} WinSentinel Security Report", emoji = true } },
            new { type = "section", fields = new object[]
            {
                new { type = "mrkdwn", text = $"*Score:* {report.SecurityScore}/100 ({grade}){deltaText}" },
                new { type = "mrkdwn", text = $"*Scan Time:* {report.GeneratedAt:yyyy-MM-dd HH:mm}" }
            }},
            new { type = "section", fields = new object[]
            {
                new { type = "mrkdwn", text = $"*Critical:* {report.TotalCritical}" },
                new { type = "mrkdwn", text = $"*Warnings:* {report.TotalWarnings}" },
                new { type = "mrkdwn", text = $"*Info:* {report.TotalInfo}" },
                new { type = "mrkdwn", text = $"*Pass:* {report.TotalPass}" }
            }}
        };

        if (!string.IsNullOrEmpty(findingsText))
            blocks.Add(new { type = "section", text = new { type = "mrkdwn", text = $"*Top Findings:*\n{findingsText}" } });

        return JsonSerializer.Serialize(new { blocks }, _jsonOptions);
    }

    private string BuildDiscordPayload(SecurityReport report, SecurityReport? previous)
    {
        var emoji = GetGradeEmoji(report.SecurityScore);
        var grade = GetGrade(report.SecurityScore);
        var deltaText = FormatDelta(report, previous);

        var color = report.SecurityScore switch
        {
            >= 90 => 0x2ECC71, >= 70 => 0xF1C40F, >= 50 => 0xE67E22, _ => 0xE74C3C
        };

        var fields = new List<object>
        {
            new { name = "Score", value = $"{report.SecurityScore}/100 ({grade}){deltaText}", inline = true },
            new { name = "Critical", value = report.TotalCritical.ToString(), inline = true },
            new { name = "Warnings", value = report.TotalWarnings.ToString(), inline = true },
            new { name = "Info", value = report.TotalInfo.ToString(), inline = true },
            new { name = "Pass", value = report.TotalPass.ToString(), inline = true }
        };

        var topFindings = GetTopFindings(report, 5);
        if (topFindings.Count > 0)
        {
            var findingsText = string.Join("\n", topFindings.Select(f =>
                $"{(f.Severity == Severity.Critical ? "🔴" : "⚠️")} {f.Title}"));
            fields.Add(new { name = "Top Findings", value = findingsText, inline = false });
        }

        var embed = new
        {
            title = $"{emoji} WinSentinel Security Report",
            color,
            fields,
            timestamp = report.GeneratedAt.ToString("o"),
            footer = new { text = "WinSentinel" }
        };

        return JsonSerializer.Serialize(new { embeds = new[] { embed } }, _jsonOptions);
    }

    private string BuildTeamsPayload(SecurityReport report, SecurityReport? previous)
    {
        var emoji = GetGradeEmoji(report.SecurityScore);
        var grade = GetGrade(report.SecurityScore);
        var deltaText = FormatDelta(report, previous);

        var topFindings = GetTopFindings(report, 5);
        var findingsText = topFindings.Count > 0
            ? string.Join("\n\n", topFindings.Select(f =>
                $"**{(f.Severity == Severity.Critical ? "🔴 Critical" : "⚠️ Warning")}**: {f.Title}"))
            : "_No critical or warning findings._";

        var card = new
        {
            type = "message",
            attachments = new[]
            {
                new
                {
                    contentType = "application/vnd.microsoft.card.adaptive",
                    content = new
                    {
                        type = "AdaptiveCard",
                        version = "1.4",
                        body = new object[]
                        {
                            new { type = "TextBlock", text = $"{emoji} WinSentinel Security Report", weight = "Bolder", size = "Large" },
                            new { type = "FactSet", facts = new object[]
                            {
                                new { title = "Score", value = $"{report.SecurityScore}/100 ({grade}){deltaText}" },
                                new { title = "Critical", value = report.TotalCritical.ToString() },
                                new { title = "Warnings", value = report.TotalWarnings.ToString() },
                                new { title = "Scan Time", value = report.GeneratedAt.ToString("yyyy-MM-dd HH:mm UTC") }
                            }},
                            new { type = "TextBlock", text = "Top Findings", weight = "Bolder", spacing = "Medium" },
                            new { type = "TextBlock", text = findingsText, wrap = true }
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(card, _jsonOptions);
    }

    private string BuildGenericPayload(SecurityReport report, SecurityReport? previous)
    {
        var scoreDelta = previous != null ? report.SecurityScore - previous.SecurityScore : (int?)null;

        var topFindings = GetTopFindings(report, 10)
            .Select(f => new { title = f.Title, severity = f.Severity.ToString(), description = f.Description })
            .ToList();

        var payload = new
        {
            source = "WinSentinel",
            timestamp = report.GeneratedAt,
            score = report.SecurityScore,
            grade = GetGrade(report.SecurityScore),
            scoreDelta,
            summary = new
            {
                critical = report.TotalCritical,
                warnings = report.TotalWarnings,
                info = report.TotalInfo,
                pass = report.TotalPass,
                total = report.TotalFindings
            },
            topFindings
        };

        return JsonSerializer.Serialize(payload, _jsonOptions);
    }

    private static string FormatDelta(SecurityReport current, SecurityReport? previous)
    {
        if (previous == null) return "";
        var delta = current.SecurityScore - previous.SecurityScore;
        return $" ({(delta > 0 ? "+" : "")}{delta})";
    }

    private static List<Finding> GetTopFindings(SecurityReport report, int count) =>
        report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity is Severity.Critical or Severity.Warning)
            .Take(count)
            .ToList();

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

// ── Models ──────────────────────────────────────────────────────

public class WebhookSettings
{
    public List<WebhookEndpoint> Endpoints { get; set; } = new();

    private static readonly string SettingsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly string SettingsPath =
        Path.Combine(SettingsDir, "webhook-settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static WebhookSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<WebhookSettings>(json, JsonOptions) ?? new();
            }
        }
        catch { }
        return new();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch { }
    }
}

public class WebhookEndpoint
{
    public string Name { get; set; } = "Webhook";
    public string Url { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public WebhookPlatform? Platform { get; set; }

    /// <summary>Only send when score is at or below this value.</summary>
    public int? ScoreThreshold { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity? MinimumSeverity { get; set; }

    public string? AuthorizationHeader { get; set; }
}

public class WebhookDeliveryResult
{
    public string EndpointName { get; set; } = string.Empty;
    public bool Success { get; set; }
    public int StatusCode { get; set; }
    public string? Error { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WebhookPlatform
{
    Slack,
    Discord,
    Teams,
    Generic
}
