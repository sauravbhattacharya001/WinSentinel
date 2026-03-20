using System.Net;
using System.Text.Json;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class WebhookNotifierTests
{
    private static SecurityReport CreateTestReport(int score = 75, int criticals = 2, int warnings = 5)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticals; i++)
            findings.Add(new Finding
            {
                Title = $"Critical Finding {i + 1}",
                Description = $"Critical issue {i + 1} detected",
                Severity = Severity.Critical,
                Remediation = "Fix immediately"
            });
        for (int i = 0; i < warnings; i++)
            findings.Add(new Finding
            {
                Title = $"Warning Finding {i + 1}",
                Description = $"Warning issue {i + 1} detected",
                Severity = Severity.Warning,
                Remediation = "Review and fix"
            });

        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new AuditResult
                {
                    ModuleName = "TestModule",
                    Category = "Test",
                    Findings = findings
                }
            }
        };
    }

    [Fact]
    public void DetectPlatform_Slack()
    {
        Assert.Equal(WebhookPlatform.Slack,
            WebhookNotifier.DetectPlatform("https://hooks.slack.com/services/T00/B00/xxx"));
    }

    [Fact]
    public void DetectPlatform_Discord()
    {
        Assert.Equal(WebhookPlatform.Discord,
            WebhookNotifier.DetectPlatform("https://discord.com/api/webhooks/123/abc"));
    }

    [Fact]
    public void DetectPlatform_Teams()
    {
        Assert.Equal(WebhookPlatform.Teams,
            WebhookNotifier.DetectPlatform("https://outlook.office.com/webhook/xxx"));
    }

    [Fact]
    public void DetectPlatform_Generic()
    {
        Assert.Equal(WebhookPlatform.Generic,
            WebhookNotifier.DetectPlatform("https://example.com/webhook"));
    }

    [Fact]
    public void Preview_Generic_ContainsScore()
    {
        var report = CreateTestReport(82);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig { Url = "https://example.com/hook" };

        var preview = notifier.Preview(report, config);

        Assert.Contains("82", preview);
        Assert.Contains("score", preview);
    }

    [Fact]
    public void Preview_Slack_ContainsBlocks()
    {
        var report = CreateTestReport(90);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://hooks.slack.com/services/T/B/x"
        };

        var preview = notifier.Preview(report, config);
        Assert.Contains("blocks", preview);
        Assert.Contains("header", preview);
    }

    [Fact]
    public void Preview_Discord_ContainsEmbeds()
    {
        var report = CreateTestReport(60);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://discord.com/api/webhooks/123/abc"
        };

        var preview = notifier.Preview(report, config);
        Assert.Contains("embeds", preview);
        Assert.Contains("color", preview);
    }

    [Fact]
    public void Preview_Teams_ContainsSections()
    {
        var report = CreateTestReport(45);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://outlook.office.com/webhook/xxx"
        };

        var preview = notifier.Preview(report, config);
        Assert.Contains("sections", preview);
        Assert.Contains("themeColor", preview);
    }

    [Fact]
    public void Preview_NoFindings_WhenDisabled()
    {
        var report = CreateTestReport(70);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://example.com/hook",
            IncludeFindings = false
        };

        var preview = notifier.Preview(report, config);
        Assert.DoesNotContain("Critical Finding 1", preview);
    }

    [Fact]
    public void Preview_RespectsMaxFindings()
    {
        var report = CreateTestReport(50, criticals: 10, warnings: 10);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://example.com/hook",
            MaxFindings = 3
        };

        var preview = notifier.Preview(report, config);
        var doc = JsonDocument.Parse(preview);
        var findings = doc.RootElement.GetProperty("findings");
        Assert.True(findings.GetArrayLength() <= 3);
    }

    [Fact]
    public void Preview_CustomTitle()
    {
        var report = CreateTestReport();
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://example.com/hook",
            CustomTitle = "My Custom Report"
        };

        var preview = notifier.Preview(report, config);
        Assert.Contains("My Custom Report", preview);
    }

    [Fact]
    public async Task SendAsync_EmptyUrl_ReturnsFalse()
    {
        var report = CreateTestReport();
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig { Url = "" };

        var result = await notifier.SendAsync(report, config);
        Assert.False(result.Success);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Preview_SeverityFilter_OnlyIncludesCritical()
    {
        var report = CreateTestReport(50, criticals: 2, warnings: 5);
        var notifier = new WebhookNotifier();
        var config = new WebhookConfig
        {
            Url = "https://example.com/hook",
            MinSeverity = Severity.Critical
        };

        var preview = notifier.Preview(report, config);
        var doc = JsonDocument.Parse(preview);
        var findings = doc.RootElement.GetProperty("findings");
        Assert.Equal(2, findings.GetArrayLength());
    }
}
