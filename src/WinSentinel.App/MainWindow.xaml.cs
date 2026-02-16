using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using WinSentinel.App.Services;
using WinSentinel.App.Views;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App;

public partial class MainWindow : Window
{
    private ScanScheduler? _scheduler;
    private NotificationService? _notificationService;
    private TrayIconService? _trayService;
    private ScheduleSettings _settings;

    /// <summary>
    /// When true, the window close will not be intercepted (actual exit).
    /// Set by TrayIconService.ExitApplication() via the ExitRequested event.
    /// </summary>
    internal bool ForceClose { get; set; }

    public MainWindow()
    {
        InitializeComponent();
        _settings = ScheduleSettings.Load();
        ContentFrame.Navigate(new DashboardPage());
        InitializeScheduler();
        InitializeTray();

        // Handle --minimized startup
        if (App.StartMinimized)
        {
            // Don't show the window on startup; it will be hidden after Loaded
            Loaded += (_, _) =>
            {
                _trayService?.MinimizeToTray();
            };
        }
    }

    private void InitializeScheduler()
    {
        var engine = new AuditEngine();
        _scheduler = new ScanScheduler(engine, _settings);
        _notificationService = new NotificationService(_settings);

        _scheduler.ScanCompleted += (_, args) =>
        {
            _notificationService.NotifyScanResult(args);
            // Also send tray balloon notification
            _trayService?.NotifyScanComplete(args);
        };

        if (_settings.Enabled)
        {
            _scheduler.Start();
        }
    }

    private void InitializeTray()
    {
        _trayService = new TrayIconService(this, _settings);
        _trayService.Initialize();

        if (_scheduler != null)
            _trayService.SetScheduler(_scheduler);

        // Wire up context menu events
        _trayService.ScanRequested += (_, _) =>
        {
            ContentFrame.Navigate(new DashboardPage());
        };

        _trayService.ExportRequested += (_, _) =>
        {
            ContentFrame.Navigate(new DashboardPage());
        };

        _trayService.SettingsRequested += (_, _) =>
        {
            NavSettings_Click(this, new RoutedEventArgs());
        };

        _trayService.ViewScoreRequested += (_, _) =>
        {
            ContentFrame.Navigate(new DashboardPage());
        };

        _trayService.BalloonClicked += (_, action) =>
        {
            ContentFrame.Navigate(new DashboardPage());
        };
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
        => ContentFrame.Navigate(new DashboardPage());

    private void NavChat_Click(object sender, RoutedEventArgs e)
        => ContentFrame.Navigate(new ChatPage());

    private void NavSettings_Click(object sender, RoutedEventArgs e)
    {
        var settingsPage = new SettingsPage();
        if (_scheduler != null)
            settingsPage.SetScheduler(_scheduler);
        if (_trayService != null)
            settingsPage.SetTrayService(_trayService);
        ContentFrame.Navigate(settingsPage);
    }

    private void NavAudit_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string category)
            ContentFrame.Navigate(new AuditDetailPage(category));
    }

    /// <summary>
    /// Intercept the window close. If minimize-to-tray is enabled, hide instead of close.
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!ForceClose && _trayService != null && _trayService.HandleWindowClosing())
        {
            e.Cancel = true;
            return;
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _scheduler?.Dispose();
        _trayService?.Dispose();
        base.OnClosed(e);
    }
}
