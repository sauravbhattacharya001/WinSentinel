using System.Windows;
using System.Windows.Controls;
using WinSentinel.App.Views;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App;

public partial class MainWindow : Window
{
    private ScanScheduler? _scheduler;
    private NotificationService? _notificationService;

    public MainWindow()
    {
        InitializeComponent();
        ContentFrame.Navigate(new DashboardPage());
        InitializeScheduler();
    }

    private void InitializeScheduler()
    {
        var settings = ScheduleSettings.Load();
        var engine = new AuditEngine();
        _scheduler = new ScanScheduler(engine, settings);
        _notificationService = new NotificationService(settings);

        _scheduler.ScanCompleted += (_, args) =>
        {
            _notificationService.NotifyScanResult(args);
        };

        if (settings.Enabled)
        {
            _scheduler.Start();
        }
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
        ContentFrame.Navigate(settingsPage);
    }

    private void NavAudit_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string category)
            ContentFrame.Navigate(new AuditDetailPage(category));
    }

    protected override void OnClosed(EventArgs e)
    {
        _scheduler?.Dispose();
        base.OnClosed(e);
    }
}
