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
    private AgentConnectionService? _agentConnection;

    /// <summary>
    /// When true, the window close will not be intercepted (actual exit).
    /// Set by TrayIconService.ExitApplication() via the ExitRequested event.
    /// </summary>
    internal bool ForceClose { get; set; }

    public MainWindow()
    {
        InitializeComponent();
        _settings = ScheduleSettings.Load();
        InitializeScheduler();
        InitializeTray();
        InitializeAgentConnection();
        NavigateToDashboard();

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
            NavigateToDashboard();
        };

        _trayService.ExportRequested += (_, _) =>
        {
            NavigateToDashboard();
        };

        _trayService.SettingsRequested += (_, _) =>
        {
            NavSettings_Click(this, new RoutedEventArgs());
        };

        _trayService.ViewScoreRequested += (_, _) =>
        {
            NavigateToDashboard();
        };

        _trayService.BalloonClicked += (_, action) =>
        {
            NavigateToDashboard();
        };
    }

    private void InitializeAgentConnection()
    {
        _agentConnection = new AgentConnectionService(Dispatcher);

        // Update status bar when connection status changes
        _agentConnection.StatusChanged += OnAgentStatusChanged;
        _agentConnection.AgentStatusUpdated += OnAgentStatusUpdated;
        _agentConnection.ThreatReceived += OnAgentThreatReceived;

        // Auto-connect on startup
        _ = _agentConnection.ConnectAsync();
    }

    private void OnAgentStatusChanged(ConnectionStatus status)
    {
        Dispatcher.InvokeAsync(() =>
        {
            AgentStatusIcon.Text = _agentConnection!.StatusIcon;
            AgentStatusText.Text = $"Agent {_agentConnection.StatusText}";

            ReconnectButton.Visibility = status == ConnectionStatus.Connected
                ? Visibility.Collapsed
                : Visibility.Visible;

            ReconnectButton.Content = status == ConnectionStatus.Connecting
                ? "⏳ Connecting..."
                : "🔌 Connect Agent";
            ReconnectButton.IsEnabled = status != ConnectionStatus.Connecting;
        });
    }

    private void OnAgentStatusUpdated(IpcAgentStatus status)
    {
        Dispatcher.InvokeAsync(() =>
        {
            AgentUptimeText.Text = status.UptimeFormatted;
            ActiveMonitorsText.Text = $"{status.ActiveModules.Count} monitors";
            ThreatsTodayText.Text = $"{status.ThreatsDetectedToday} threats";
            LastScanText.Text = status.LastScanTime?.ToLocalTime().ToString("HH:mm:ss") ?? "Never";
        });
    }

    private void OnAgentThreatReceived(IpcThreatEvent threat)
    {
        Dispatcher.InvokeAsync(() =>
        {
            // Update threats count in status bar
            if (_agentConnection != null)
                ThreatsTodayText.Text = $"{_agentConnection.ThreatsToday} threats";

            // Update critical badge
            UpdateCriticalBadge();

            // Show toast for critical threats
            if (threat.Severity == "Critical")
            {
                try
                {
                    var sender = new WindowsToastSender();
                    sender.ShowToast(
                        $"🔴 CRITICAL: {threat.Title}",
                        $"Source: {threat.Source}\n{threat.Description}",
                        ToastUrgency.High);
                }
                catch { /* best-effort */ }
            }
        });
    }

    private void UpdateCriticalBadge()
    {
        if (_agentConnection == null) return;

        var count = _agentConnection.UnreadCriticalCount;
        CriticalBadge.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
        CriticalBadgeText.Text = count > 99 ? "99+" : count.ToString();
    }

    // ── Navigation ──

    private void NavigateToDashboard()
    {
        var page = new DashboardPage();
        if (_agentConnection != null)
            page.SetAgentService(_agentConnection);
        ContentFrame.Navigate(page);
    }

    private void NavThreatFeed_Click(object sender, RoutedEventArgs e)
    {
        var page = new ThreatFeedPage();
        if (_agentConnection != null)
            page.SetAgentService(_agentConnection);
        ContentFrame.Navigate(page);

        // Clear badge
        if (_agentConnection != null)
            _agentConnection.UnreadCriticalCount = 0;
        UpdateCriticalBadge();
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
    {
        var page = new DashboardPage();
        if (_agentConnection != null)
            page.SetAgentService(_agentConnection);
        ContentFrame.Navigate(page);
    }

    private void NavChat_Click(object sender, RoutedEventArgs e)
    {
        var chatPage = new ChatPage();
        if (_agentConnection != null)
            chatPage.SetAgentService(_agentConnection);
        ContentFrame.Navigate(chatPage);
    }

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

    private async void ReconnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_agentConnection != null)
        {
            _agentConnection.Disconnect();
            await _agentConnection.ConnectAsync();
        }
    }

    /// <summary>
    /// Navigate to the threat feed and scroll to a specific threat (for toast click).
    /// </summary>
    public void NavigateToThreat(string threatId)
    {
        var page = new ThreatFeedPage();
        if (_agentConnection != null)
            page.SetAgentService(_agentConnection);
        ContentFrame.Navigate(page);
        page.ScrollToThreat(threatId);
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
        _agentConnection?.Dispose();
        base.OnClosed(e);
    }
}
