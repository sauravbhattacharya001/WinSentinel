using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class NotificationServiceTests
{
    private class FakeToastSender : IToastSender
    {
        public List<(string title, string body, ToastUrgency urgency)> SentToasts { get; } = new();

        public void ShowToast(string title, string body, ToastUrgency urgency)
        {
            SentToasts.Add((title, body, urgency));
        }
    }

    private static ScanCompletedEventArgs CreateArgs(
        int score = 85, int? previousScore = null,
        int criticalCount = 0, int warningCount = 0,
        bool isScheduled = true)
    {
        var findings = new List<Finding>();
        for (int i = 0; i < criticalCount; i++)
            findings.Add(Finding.Critical($"Critical {i}", "Test", "Test"));
        for (int i = 0; i < warningCount; i++)
            findings.Add(Finding.Warning($"Warning {i}", "Test", "Test"));

        var report = new SecurityReport
        {
            SecurityScore = score,
            Results = new()
            {
                new AuditResult
                {
                    ModuleName = "Test",
                    Category = "Test",
                    Findings = findings
                }
            }
        };

        return new ScanCompletedEventArgs
        {
            Report = report,
            PreviousScore = previousScore,
            IsScheduled = isScheduled
        };
    }

    [Fact]
    public void ShouldNotify_WhenScoreDrops_ReturnsTrue()
    {
        var settings = new ScheduleSettings { NotifyOnScoreDrop = true };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(score: 60, previousScore: 85);

        Assert.True(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_WhenScoreImproves_NotifyOnDropOnly_ReturnsFalse()
    {
        var settings = new ScheduleSettings
        {
            NotifyOnScoreDrop = true,
            NotifyOnComplete = false,
            NotifyOnNewFindings = false
        };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(score: 90, previousScore: 85);

        Assert.False(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_ScheduledScanComplete_ReturnsTrue()
    {
        var settings = new ScheduleSettings { NotifyOnComplete = true };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(isScheduled: true);

        Assert.True(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_ManualScanComplete_WithOnlyNotifyOnComplete_ReturnsFalse()
    {
        var settings = new ScheduleSettings
        {
            NotifyOnComplete = true,
            NotifyOnScoreDrop = false,
            NotifyOnNewFindings = false
        };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(isScheduled: false);

        Assert.False(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_NewCriticalFindings_ReturnsTrue()
    {
        var settings = new ScheduleSettings { NotifyOnNewFindings = true };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(criticalCount: 2);

        Assert.True(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_NewWarnings_ReturnsTrue()
    {
        var settings = new ScheduleSettings { NotifyOnNewFindings = true };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(warningCount: 3);

        Assert.True(service.ShouldNotify(args));
    }

    [Fact]
    public void ShouldNotify_AllDisabled_ReturnsFalse()
    {
        var settings = new ScheduleSettings
        {
            NotifyOnComplete = false,
            NotifyOnScoreDrop = false,
            NotifyOnNewFindings = false
        };
        var service = new NotificationService(settings, new FakeToastSender());
        var args = CreateArgs(isScheduled: true);

        Assert.False(service.ShouldNotify(args));
    }

    [Fact]
    public void NotifyScanResult_SendsToast_WhenShouldNotify()
    {
        var fake = new FakeToastSender();
        var settings = new ScheduleSettings { NotifyOnComplete = true };
        var service = new NotificationService(settings, fake);
        var args = CreateArgs(score: 85, isScheduled: true);

        service.NotifyScanResult(args);

        Assert.Single(fake.SentToasts);
        Assert.Contains("85", fake.SentToasts[0].title);
    }

    [Fact]
    public void NotifyScanResult_SkipsToast_WhenShouldNotNotify()
    {
        var fake = new FakeToastSender();
        var settings = new ScheduleSettings
        {
            NotifyOnComplete = false,
            NotifyOnScoreDrop = false,
            NotifyOnNewFindings = false
        };
        var service = new NotificationService(settings, fake);
        var args = CreateArgs(score: 100, isScheduled: false);

        service.NotifyScanResult(args);

        Assert.Empty(fake.SentToasts);
    }

    [Fact]
    public void BuildTitle_ScoreDropped_ShowsWarning()
    {
        var args = CreateArgs(score: 60, previousScore: 85);
        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Dropped", title);
        Assert.Contains("60", title);
    }

    [Fact]
    public void BuildTitle_CriticalFindings_ShowsCritical()
    {
        var args = CreateArgs(score: 50, criticalCount: 3);
        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Critical", title);
        Assert.Contains("3", title);
    }

    [Fact]
    public void BuildTitle_WarningsOnly_ShowsWarnings()
    {
        var args = CreateArgs(score: 80, warningCount: 5);
        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Warning", title);
    }

    [Fact]
    public void BuildTitle_AllClear_ShowsSuccess()
    {
        var args = CreateArgs(score: 100);
        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Complete", title);
        Assert.Contains("100", title);
    }

    [Fact]
    public void BuildBody_IncludesScore()
    {
        var args = CreateArgs(score: 72);
        var body = NotificationService.BuildBody(args);
        Assert.Contains("72", body);
        Assert.Contains("C", body); // Grade C
    }

    [Fact]
    public void BuildBody_WithPreviousScore_ShowsDelta()
    {
        var args = CreateArgs(score: 70, previousScore: 85);
        var body = NotificationService.BuildBody(args);
        Assert.Contains("↓", body);
        Assert.Contains("15", body);
        Assert.Contains("85", body);
    }

    [Fact]
    public void BuildBody_WithImprovingScore_ShowsUpArrow()
    {
        var args = CreateArgs(score: 90, previousScore: 80);
        var body = NotificationService.BuildBody(args);
        Assert.Contains("↑", body);
    }

    [Fact]
    public void NotifyScanResult_HighUrgency_ForCriticalFindings()
    {
        var fake = new FakeToastSender();
        var settings = new ScheduleSettings { NotifyOnNewFindings = true };
        var service = new NotificationService(settings, fake);
        var args = CreateArgs(score: 40, criticalCount: 2);

        service.NotifyScanResult(args);

        Assert.Single(fake.SentToasts);
        Assert.Equal(ToastUrgency.High, fake.SentToasts[0].urgency);
    }

    [Fact]
    public void NotifyScanResult_NormalUrgency_ForWarnings()
    {
        var fake = new FakeToastSender();
        var settings = new ScheduleSettings { NotifyOnNewFindings = true };
        var service = new NotificationService(settings, fake);
        var args = CreateArgs(score: 80, warningCount: 2);

        service.NotifyScanResult(args);

        Assert.Single(fake.SentToasts);
        Assert.Equal(ToastUrgency.Normal, fake.SentToasts[0].urgency);
    }
}
