using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using WinSentinel.App.Services;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class DashboardPage : Page
{
    private DashboardViewModel _viewModel;
    private AgentConnectionService? _agentConnection;
    private readonly AuditHistoryService _historyService = new();

    public DashboardPage()
    {
        InitializeComponent();
        _viewModel = new DashboardViewModel(Dispatcher);

        // Wire up collections to UI
        _viewModel.PropertyChanged += ViewModel_PropertyChanged;
        _viewModel.MonitorCards.CollectionChanged += MonitorCards_CollectionChanged;
        _viewModel.RecentThreats.CollectionChanged += RecentThreats_CollectionChanged;
        _viewModel.TimelineEntries.CollectionChanged += TimelineEntries_CollectionChanged;

        // Bind collections
        MonitorCardsList.ItemsSource = _viewModel.MonitorCards;
        RecentThreatsList.ItemsSource = _viewModel.RecentThreats;
        TimelineList.ItemsSource = _viewModel.TimelineEntries;
    }

    /// <summary>
    /// Set the agent connection service (called from MainWindow during navigation).
    /// </summary>
    public void SetAgentService(AgentConnectionService connection)
    {
        _agentConnection = connection;
        _viewModel.SetAgentConnection(connection);
    }

    // ══════════════════════════════════════════
    //  Property Change Handler
    // ══════════════════════════════════════════

    private void ViewModel_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        Dispatcher.InvokeAsync(() =>
        {
            switch (e.PropertyName)
            {
                case nameof(DashboardViewModel.AgentStatusIcon):
                    AgentStatusIconText.Text = _viewModel.AgentStatusIcon;
                    break;

                case nameof(DashboardViewModel.AgentStatusText):
                    AgentStatusLabel.Text = _viewModel.AgentStatusText;
                    break;

                case nameof(DashboardViewModel.UptimeText):
                    UptimeLabel.Text = _viewModel.UptimeText;
                    break;

                case nameof(DashboardViewModel.SecurityScoreDisplay):
                    ScoreText.Text = _viewModel.SecurityScoreDisplay;
                    break;

                case nameof(DashboardViewModel.SecurityGrade):
                    GradeText.Text = _viewModel.SecurityGrade;
                    break;

                case nameof(DashboardViewModel.ScoreColor):
                    try
                    {
                        var color = (Color)ColorConverter.ConvertFromString(_viewModel.ScoreColor);
                        ScoreRing.Stroke = new SolidColorBrush(color);
                    }
                    catch { /* fallback */ }
                    break;

                case nameof(DashboardViewModel.ScoreTrendArrow):
                    TrendArrowText.Text = _viewModel.ScoreTrendArrow;
                    break;

                case nameof(DashboardViewModel.ScoreTrendText):
                    TrendDescText.Text = _viewModel.ScoreTrendText;
                    break;

                case nameof(DashboardViewModel.ScoreTrendColor):
                    try
                    {
                        var color = (Color)ColorConverter.ConvertFromString(_viewModel.ScoreTrendColor);
                        TrendArrowText.Foreground = new SolidColorBrush(color);
                        TrendDescText.Foreground = new SolidColorBrush(color);
                    }
                    catch { /* fallback */ }
                    break;

                case nameof(DashboardViewModel.IsConnected):
                    DisconnectedBanner.Visibility = _viewModel.IsConnected ? Visibility.Collapsed : Visibility.Visible;
                    break;

                case nameof(DashboardViewModel.IsScanRunning):
                    ScanProgressPanel.Visibility = _viewModel.IsScanRunning ? Visibility.Visible : Visibility.Collapsed;
                    RunAuditButton.IsEnabled = _viewModel.CanRunAudit;
                    RunAuditButton.Opacity = _viewModel.CanRunAudit ? 1.0 : 0.5;
                    break;

                case nameof(DashboardViewModel.CriticalCount):
                    CritCountText.Text = _viewModel.CriticalCount.ToString();
                    break;

                case nameof(DashboardViewModel.HighCount):
                    HighCountText.Text = _viewModel.HighCount.ToString();
                    break;

                case nameof(DashboardViewModel.MediumCount):
                    MedCountText.Text = _viewModel.MediumCount.ToString();
                    break;

                case nameof(DashboardViewModel.LowCount):
                    LowCountText.Text = _viewModel.LowCount.ToString();
                    break;

                case nameof(DashboardViewModel.AutoFixesToday):
                    AutoFixCountText.Text = _viewModel.AutoFixesToday.ToString();
                    break;

                case nameof(DashboardViewModel.LastActionText):
                    LastActionLabel.Text = _viewModel.LastActionText;
                    break;

                case nameof(DashboardViewModel.PauseResumeText):
                    PauseResumeButton.Content = _viewModel.PauseResumeText;
                    break;
            }
        });
    }

    // ══════════════════════════════════════════
    //  Collection Change Handlers
    // ══════════════════════════════════════════

    private void MonitorCards_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.InvokeAsync(() =>
        {
            NoMonitorsText.Visibility = _viewModel.MonitorCards.Count == 0
                ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    private void RecentThreats_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.InvokeAsync(() =>
        {
            NoThreatsText.Visibility = _viewModel.RecentThreats.Count == 0
                ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    private void TimelineEntries_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.InvokeAsync(() =>
        {
            NoTimelineText.Visibility = _viewModel.TimelineEntries.Count == 0
                ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    // ══════════════════════════════════════════
    //  Button Click Handlers
    // ══════════════════════════════════════════

    private async void RunAuditButton_Click(object sender, RoutedEventArgs e)
    {
        if (_agentConnection != null && _agentConnection.IsConnected)
        {
            // Run via agent IPC
            await _viewModel.RunFullAuditAsync();
        }
        else
        {
            // Fallback: run locally
            await RunLocalAuditAsync();
        }
    }

    private async Task RunLocalAuditAsync()
    {
        RunAuditButton.IsEnabled = false;
        RunAuditButton.Opacity = 0.5;
        ScanProgressPanel.Visibility = Visibility.Visible;

        try
        {
            var engine = new AuditEngine();
            engine.SetHistoryService(_historyService);

            var progress = new Progress<(string module, int current, int total)>(p =>
            {
                Dispatcher.Invoke(() =>
                {
                    AgentStatusLabel.Text = $"Scanning: {p.module}...";
                });
            });

            var report = await engine.RunFullAuditAsync(progress);

            Dispatcher.Invoke(() =>
            {
                ScoreText.Text = $"{report.SecurityScore}";
                GradeText.Text = SecurityScorer.GetGrade(report.SecurityScore);
                AgentStatusLabel.Text = $"Scan complete — Score: {report.SecurityScore}";

                try
                {
                    var color = (Color)ColorConverter.ConvertFromString(SecurityScorer.GetScoreColor(report.SecurityScore));
                    ScoreRing.Stroke = new SolidColorBrush(color);
                }
                catch { }

                // Add to timeline
                _viewModel.TimelineEntries.Add(new TimelineEntry
                {
                    Time = DateTime.Now.ToString("HH:mm"),
                    Icon = "📊",
                    Description = $"Local audit completed — Score: {report.SecurityScore}/100 ({SecurityScorer.GetGrade(report.SecurityScore)})",
                    EntryType = TimelineEntryType.Info
                });
            });
        }
        catch (Exception ex)
        {
            AgentStatusLabel.Text = $"Scan failed: {ex.Message}";
        }
        finally
        {
            RunAuditButton.IsEnabled = true;
            RunAuditButton.Opacity = 1.0;
            ScanProgressPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void PauseResumeButton_Click(object sender, RoutedEventArgs e)
    {
        // Toggle pause state (visual only for now — would need IPC command for actual pause)
        _viewModel.AllMonitorsPaused = !_viewModel.AllMonitorsPaused;
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export Security Report",
            Filter = "HTML Report (*.html)|*.html|JSON Report (*.json)|*.json|Text Report (*.txt)|*.txt",
            FileName = ReportGenerator.GenerateFilename(ReportFormat.Html),
            DefaultExt = ".html",
            AddExtension = true
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var format = dialog.FilterIndex switch
                {
                    1 => ReportFormat.Html,
                    2 => ReportFormat.Json,
                    3 => ReportFormat.Text,
                    _ => ReportFormat.Html
                };

                ScoreTrendSummary? trend = null;
                try
                {
                    trend = _historyService.GetTrend(30);
                    if (trend.TotalScans == 0) trend = null;
                }
                catch { }

                // We need a report to export — run a quick audit if none available
                var engine = new AuditEngine();
                engine.SetHistoryService(_historyService);

                var report = engine.RunFullAuditAsync(null).GetAwaiter().GetResult();

                var generator = new ReportGenerator();
                generator.SaveReport(dialog.FileName, report, format, trend);

                var result = MessageBox.Show(
                    $"Report exported successfully!\n\n{dialog.FileName}\n\nOpen the file now?",
                    "Export Complete", MessageBoxButton.YesNo, MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = dialog.FileName,
                            UseShellExecute = true
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export report:\n\n{ex.Message}", "Export Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void OpenChatButton_Click(object sender, RoutedEventArgs e)
    {
        // Navigate to Chat page via MainWindow
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            var chatPage = new ChatPage();
            if (_agentConnection != null)
                chatPage.SetAgentService(_agentConnection);
            mainWindow.ContentFrame.Navigate(chatPage);
        }
    }

    private void ViewAllThreats_Click(object sender, RoutedEventArgs e)
    {
        // Navigate to Threat Feed page via MainWindow
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            var page = new ThreatFeedPage();
            if (_agentConnection != null)
                page.SetAgentService(_agentConnection);
            mainWindow.ContentFrame.Navigate(page);
        }
    }

    private async void ReconnectButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.ReconnectAsync();
    }
}
