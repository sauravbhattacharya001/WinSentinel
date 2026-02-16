using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Sends Windows toast notifications for scan results.
/// Uses Microsoft.Toolkit.Uwp.Notifications (CommunityToolkit.WinUI.Notifications on .NET 8).
/// This service uses a simple abstraction so it works in test environments too.
/// </summary>
public class NotificationService
{
    private readonly ScheduleSettings _settings;
    private readonly IToastSender _toastSender;

    public NotificationService(ScheduleSettings settings, IToastSender? toastSender = null)
    {
        _settings = settings;
        _toastSender = toastSender ?? new WindowsToastSender();
    }

    /// <summary>
    /// Evaluate scan results and send appropriate notifications.
    /// </summary>
    public void NotifyScanResult(ScanCompletedEventArgs args)
    {
        if (!ShouldNotify(args)) return;

        var report = args.Report;
        var title = BuildTitle(args);
        var body = BuildBody(args);
        var urgency = DetermineUrgency(args);

        _toastSender.ShowToast(title, body, urgency);
    }

    public bool ShouldNotify(ScanCompletedEventArgs args)
    {
        // Check individual notification preferences
        if (_settings.NotifyOnComplete && args.IsScheduled)
            return true;

        if (_settings.NotifyOnScoreDrop && args.ScoreDropped)
            return true;

        if (_settings.NotifyOnNewFindings &&
            (args.Report.TotalCritical > 0 || args.Report.TotalWarnings > 0))
            return true;

        return false;
    }

    public static string BuildTitle(ScanCompletedEventArgs args)
    {
        if (args.ScoreDropped)
            return $"⚠️ Security Score Dropped: {args.Report.SecurityScore}/100";

        if (args.Report.TotalCritical > 0)
            return $"🔴 {args.Report.TotalCritical} Critical Finding(s) Detected";

        if (args.Report.TotalWarnings > 0)
            return $"🟡 {args.Report.TotalWarnings} Warning(s) Found";

        return $"✅ Scan Complete — Score: {args.Report.SecurityScore}/100";
    }

    public static string BuildBody(ScanCompletedEventArgs args)
    {
        var report = args.Report;
        var lines = new List<string>();

        lines.Add($"Security Score: {report.SecurityScore}/100 ({SecurityScorer.GetGrade(report.SecurityScore)})");

        if (args.PreviousScore.HasValue)
        {
            var delta = args.ScoreDelta;
            var arrow = delta > 0 ? "↑" : delta < 0 ? "↓" : "→";
            lines.Add($"Change: {arrow} {Math.Abs(delta)} points (was {args.PreviousScore})");
        }

        if (report.TotalCritical > 0 || report.TotalWarnings > 0)
        {
            lines.Add($"Findings: {report.TotalCritical} critical, {report.TotalWarnings} warnings");
        }
        else
        {
            lines.Add("No critical issues or warnings found!");
        }

        return string.Join("\n", lines);
    }

    private static ToastUrgency DetermineUrgency(ScanCompletedEventArgs args)
    {
        if (args.Report.TotalCritical > 0 || args.ScoreDropped)
            return ToastUrgency.High;

        if (args.Report.TotalWarnings > 0)
            return ToastUrgency.Normal;

        return ToastUrgency.Low;
    }
}

/// <summary>Toast urgency levels.</summary>
public enum ToastUrgency
{
    Low,
    Normal,
    High
}

/// <summary>Abstraction for sending toast notifications (testable).</summary>
public interface IToastSender
{
    void ShowToast(string title, string body, ToastUrgency urgency);
}

/// <summary>
/// Windows toast notification sender using the Windows notification system.
/// Works on Windows 10+ without UWP dependencies via raw XML.
/// </summary>
public class WindowsToastSender : IToastSender
{
    public void ShowToast(string title, string body, ToastUrgency urgency)
    {
        try
        {
            // Use Windows.UI.Notifications via reflection/COM to avoid heavy UWP dependencies
            // For .NET 8 desktop apps, we use the simpler approach via PowerShell
            SendToastViaPowerShell(title, body);
        }
        catch
        {
            // Toast notification is best-effort — don't crash the app
        }
    }

    private static void SendToastViaPowerShell(string title, string body)
    {
        var escapedTitle = title.Replace("'", "''").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
        var escapedBody = body.Replace("'", "''").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\n", "&#10;");

        var xml = $@"<toast>
  <visual>
    <binding template=""ToastGeneric"">
      <text>{escapedTitle}</text>
      <text>{escapedBody}</text>
      <image placement=""appLogoOverride"" hint-crop=""circle"" src="""" />
    </binding>
  </visual>
  <audio silent=""false"" />
</toast>";

        var script = $@"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('{xml.Replace("'", "''")}')
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('WinSentinel')
$notifier.Show($toast)
";

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = System.Diagnostics.Process.Start(psi);
        process?.WaitForExit(10000);
    }
}
