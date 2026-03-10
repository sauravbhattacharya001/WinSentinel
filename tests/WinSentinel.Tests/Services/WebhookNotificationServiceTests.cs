using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class WebhookNotificationServiceTests
{
    private static SecurityReport CreateTestReport(int score = 75, int criticals = 1, int warnings = 2)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticals; i++)
            findings.Add(new Finding { Title = $"Critical-{i}", Severity = Severity.Critical, Description = "Critical issue" });
        for (int i = 0; i < warnings; i++)
            findings.Add(new Finding { Title = $"Warning-{i}", Severity = Severity.Warning, Description = "Warning issue" });
        findings.Add(new Finding { Title = "Info-0", Severity = Severity.Info, Description = "Info item" });
        findings.Add(new Finding { Title = "Pass-0", Severity = Severity.Pass, Description = "Passed" });

        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new() { ModuleName = "TestModule", Category = "Test", Findings = findings }
            }
        };
    }

    [Theory]
    [InlineData("https://hooks.slack.com/services/T00/B00/xxx", WebhookPlatform.Slack)]
    [InlineData("https://discord.com/api/webhooks/123/abc", WebhookPlatform.Discord)]
    [InlineData("https://discordapp.com/api/webhooks/123/abc", WebhookPlatform.Discord)]
    [InlineData("https://org.webhook.office.com/webhookb2/xxx", WebhookPlatform.Teams)]
    [InlineData("https://example.com/my-webhook", WebhookPlatform.Generic)]
    public void DetectPlatform_CorrectlyIdentifies(string url, WebhookPlatform expected)
    {
        Assert.Equal(expected, WebhookNotificationService.DetectPlatform(url));
    }

    [Fact]
    public void ShouldNotify_NoFilters_ReturnsTrue()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com" };
        var service = new WebhookNotificationService(settings);
        Assert.True(service.ShouldNotify(endpoint, CreateTestReport()));
    }

    [Fact]
    public void ShouldNotify_ScoreAboveThreshold_ReturnsFalse()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", ScoreThreshold = 50 };
        var service = new WebhookNotificationService(settings);
        Assert.False(service.ShouldNotify(endpoint, CreateTestReport(score: 75)));
    }

    [Fact]
    public void ShouldNotify_ScoreBelowThreshold_ReturnsTrue()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", ScoreThreshold = 80 };
        var service = new WebhookNotificationService(settings);
        Assert.True(service.ShouldNotify(endpoint, CreateTestReport(score: 75)));
    }

    [Fact]
    public void ShouldNotify_MinSeverityCritical_NoCriticals_ReturnsFalse()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", MinimumSeverity = Severity.Critical };
        var service = new WebhookNotificationService(settings);
        Assert.False(service.ShouldNotify(endpoint, CreateTestReport(criticals: 0, warnings: 3)));
    }

    [Fact]
    public void ShouldNotify_MinSeverityCritical_HasCriticals_ReturnsTrue()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", MinimumSeverity = Severity.Critical };
        var service = new WebhookNotificationService(settings);
        Assert.True(service.ShouldNotify(endpoint, CreateTestReport(criticals: 2)));
    }

    [Fact]
    public void ShouldNotify_MinSeverityWarning_HasWarnings_ReturnsTrue()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", MinimumSeverity = Severity.Warning };
        var service = new WebhookNotificationService(settings);
        Assert.True(service.ShouldNotify(endpoint, CreateTestReport(criticals: 0, warnings: 1)));
    }

    [Fact]
    public void BuildPayload_Slack_ContainsBlocks()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://hooks.slack.com/services/T/B/x" };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(), null);
        Assert.Contains("blocks", payload);
        Assert.Contains("WinSentinel", payload);
    }

    [Fact]
    public void BuildPayload_Discord_ContainsEmbeds()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://discord.com/api/webhooks/123/abc" };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(), null);
        Assert.Contains("embeds", payload);
        Assert.Contains("WinSentinel", payload);
    }

    [Fact]
    public void BuildPayload_Teams_ContainsAdaptiveCard()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://org.webhook.office.com/webhookb2/xxx" };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(), null);
        Assert.Contains("AdaptiveCard", payload);
    }

    [Fact]
    public void BuildPayload_Generic_ContainsScoreAndGrade()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com/webhook" };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(score: 82), null);
        Assert.Contains("82", payload);
        Assert.Contains("grade", payload);
    }

    [Fact]
    public void BuildPayload_PlatformOverride_UsesOverride()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com", Platform = WebhookPlatform.Slack };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(), null);
        Assert.Contains("blocks", payload);
    }

    [Fact]
    public void BuildPayload_WithPreviousReport_IncludesDelta()
    {
        var settings = new WebhookSettings();
        var endpoint = new WebhookEndpoint { Url = "https://example.com" };
        var service = new WebhookNotificationService(settings);
        var payload = service.BuildPayload(endpoint, CreateTestReport(score: 80), CreateTestReport(score: 70));
        Assert.Contains("10", payload);
    }

    [Fact]
    public void WebhookSettings_RoundTrip()
    {
        var settings = new WebhookSettings
        {
            Endpoints = new List<WebhookEndpoint>
            {
                new() { Name = "Test", Url = "https://example.com", ScoreThreshold = 70,
                         MinimumSeverity = Severity.Warning, Platform = WebhookPlatform.Slack }
            }
        };

        var json = System.Text.Json.JsonSerializer.Serialize(settings);
        var loaded = System.Text.Json.JsonSerializer.Deserialize<WebhookSettings>(json);

        Assert.NotNull(loaded);
        Assert.Single(loaded!.Endpoints);
        Assert.Equal("Test", loaded.Endpoints[0].Name);
        Assert.Equal(70, loaded.Endpoints[0].ScoreThreshold);
        Assert.Equal(Severity.Warning, loaded.Endpoints[0].MinimumSeverity);
        Assert.Equal(WebhookPlatform.Slack, loaded.Endpoints[0].Platform);
    }

    [Fact]
    public async Task NotifyAsync_DisabledEndpoint_Skipped()
    {
        var settings = new WebhookSettings
        {
            Endpoints = new List<WebhookEndpoint>
            {
                new() { Name = "Disabled", Url = "https://example.com", Enabled = false }
            }
        };
        var service = new WebhookNotificationService(settings);
        var results = await service.NotifyAsync(CreateTestReport());
        Assert.Empty(results);
    }

    [Fact]
    public async Task NotifyAsync_FilterExcludesAll_EmptyResults()
    {
        var settings = new WebhookSettings
        {
            Endpoints = new List<WebhookEndpoint>
            {
                new() { Name = "Strict", Url = "https://example.com", ScoreThreshold = 30 }
            }
        };
        var service = new WebhookNotificationService(settings);
        var results = await service.NotifyAsync(CreateTestReport(score: 90));
        Assert.Empty(results);
    }
}
