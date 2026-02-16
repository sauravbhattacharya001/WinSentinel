using System.Windows;
using WinSentinel.Core.Models;

namespace WinSentinel.App;

public partial class App : Application
{
    /// <summary>
    /// Whether the app was launched with --minimized flag (e.g. from Windows startup).
    /// </summary>
    public static bool StartMinimized { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Check command-line args for --minimized
        foreach (var arg in e.Args)
        {
            if (arg.Equals("--minimized", StringComparison.OrdinalIgnoreCase))
            {
                StartMinimized = true;
                break;
            }
        }

        // Also check settings for "Start minimized" option
        var settings = ScheduleSettings.Load();
        if (settings.StartMinimized)
        {
            StartMinimized = true;
        }

        // MainWindow is created via StartupUri in XAML
    }
}
