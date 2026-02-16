using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

[Collection("SettingsFile")]
public class TraySettingsTests
{
    [Fact]
    public void DefaultSettings_TrayValues()
    {
        var settings = new ScheduleSettings();

        Assert.True(settings.MinimizeToTrayOnClose);
        Assert.False(settings.StartMinimized);
        Assert.True(settings.ShowTrayNotifications);
        Assert.False(settings.StartWithWindows);
        Assert.False(settings.HasShownTrayBalloon);
    }

    [Fact]
    public void Settings_SaveAndLoad_PreservesTrayValues()
    {
        // Save current settings so we can restore them
        var original = ScheduleSettings.Load();

        try
        {
            var settings = new ScheduleSettings
            {
                MinimizeToTrayOnClose = false,
                StartMinimized = true,
                ShowTrayNotifications = false,
                StartWithWindows = true,
                HasShownTrayBalloon = true
            };

            settings.Save();

            var loaded = ScheduleSettings.Load();

            Assert.False(loaded.MinimizeToTrayOnClose);
            Assert.True(loaded.StartMinimized);
            Assert.False(loaded.ShowTrayNotifications);
            Assert.True(loaded.StartWithWindows);
            Assert.True(loaded.HasShownTrayBalloon);
        }
        finally
        {
            // Restore original settings
            original.Save();
        }
    }

    [Fact]
    public void TrayNotification_ShouldNotify_RespectsSetting()
    {
        var settings = new ScheduleSettings
        {
            ShowTrayNotifications = true,
            NotifyOnComplete = true,
            NotifyOnScoreDrop = true,
            NotifyOnNewFindings = true
        };

        var notificationService = new NotificationService(settings, new NoOpToastSender());

        var args = new ScanCompletedEventArgs
        {
            Report = new SecurityReport
            {
                SecurityScore = 85,
                GeneratedAt = DateTimeOffset.UtcNow,
                Results = new()
            },
            PreviousScore = null,
            IsScheduled = true
        };

        // Should notify for scheduled scan completion
        Assert.True(notificationService.ShouldNotify(args));
    }

    [Fact]
    public void TrayNotification_ScoreDropped_Detected()
    {
        var args = new ScanCompletedEventArgs
        {
            Report = new SecurityReport
            {
                SecurityScore = 65,
                GeneratedAt = DateTimeOffset.UtcNow,
                Results = new()
            },
            PreviousScore = 85,
            IsScheduled = false
        };

        Assert.True(args.ScoreDropped);
        Assert.Equal(-20, args.ScoreDelta);

        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Dropped", title);
    }

    [Fact]
    public void TrayNotification_CriticalFindings_Detected()
    {
        var report = new SecurityReport
        {
            SecurityScore = 40,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new()
            {
                new AuditResult
                {
                    ModuleName = "Test",
                    Category = "Test",
                    Success = true,
                    Findings = new()
                    {
                        new Finding
                        {
                            Title = "Critical Issue",
                            Severity = Severity.Critical,
                            Description = "Something bad"
                        }
                    }
                }
            }
        };

        Assert.Equal(1, report.TotalCritical);

        var args = new ScanCompletedEventArgs
        {
            Report = report,
            PreviousScore = null,
            IsScheduled = false
        };

        var title = NotificationService.BuildTitle(args);
        Assert.Contains("Critical", title);
    }

    private class NoOpToastSender : IToastSender
    {
        public void ShowToast(string title, string body, ToastUrgency urgency) { }
    }
}
