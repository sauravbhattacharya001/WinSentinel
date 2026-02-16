using System.Windows;
using System.Windows.Controls;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

public partial class SettingsPage : Page
{
    private ScheduleSettings _settings;
    private ScanScheduler? _scheduler;
    private NotificationService? _notificationService;
    private bool _isLoading = true;

    public SettingsPage()
    {
        InitializeComponent();
        _settings = ScheduleSettings.Load();
        LoadSettingsToUI();
        _isLoading = false;
    }

    /// <summary>
    /// Set the shared scheduler instance (from App.xaml.cs).
    /// </summary>
    public void SetScheduler(ScanScheduler scheduler)
    {
        _scheduler = scheduler;
        _notificationService = new NotificationService(_settings);

        _scheduler.ScanCompleted += (_, args) =>
        {
            Dispatcher.Invoke(() =>
            {
                UpdateStatusDisplay();
                ScanStatusText.Text = $"Scan complete — Score: {args.Report.SecurityScore}/100";
                ScanNowButton.IsEnabled = true;
            });

            _notificationService?.NotifyScanResult(args);
        };

        _scheduler.ScanProgress += (_, msg) =>
        {
            Dispatcher.Invoke(() => ScanStatusText.Text = msg);
        };

        UpdateStatusDisplay();
    }

    private void LoadSettingsToUI()
    {
        EnableToggle.IsChecked = _settings.Enabled;

        IntervalHourly.IsChecked = _settings.Interval == ScanInterval.Hourly;
        IntervalDaily.IsChecked = _settings.Interval == ScanInterval.Daily;
        IntervalCustom.IsChecked = _settings.Interval == ScanInterval.Custom;

        CustomMinutesBox.Text = _settings.CustomIntervalMinutes.ToString();
        CustomIntervalPanel.Visibility = _settings.Interval == ScanInterval.Custom ? Visibility.Visible : Visibility.Collapsed;

        NotifyCompleteCheck.IsChecked = _settings.NotifyOnComplete;
        NotifyScoreDropCheck.IsChecked = _settings.NotifyOnScoreDrop;
        NotifyNewFindingsCheck.IsChecked = _settings.NotifyOnNewFindings;

        IntervalSection.Opacity = _settings.Enabled ? 1.0 : 0.5;
        IntervalSection.IsEnabled = _settings.Enabled;

        // Populate module checkboxes
        var engine = new AuditEngine();
        ModulesList.Items.Clear();
        foreach (var module in engine.Modules)
        {
            var cb = new CheckBox
            {
                Content = $"{module.Name} ({module.Category})",
                Tag = module.Category,
                IsChecked = _settings.IncludedModules.Count == 0 || _settings.IncludedModules.Contains(module.Category),
                Foreground = (System.Windows.Media.Brush)Application.Current.Resources["TextPrimary"],
                FontSize = 14,
                Margin = new Thickness(0, 0, 0, 6)
            };
            cb.Checked += Module_Changed;
            cb.Unchecked += Module_Changed;
            ModulesList.Items.Add(cb);
        }

        UpdateStatusDisplay();
    }

    private void SaveSettings()
    {
        if (_isLoading) return;

        _settings.Enabled = EnableToggle.IsChecked ?? false;

        if (IntervalHourly.IsChecked == true)
            _settings.Interval = ScanInterval.Hourly;
        else if (IntervalDaily.IsChecked == true)
            _settings.Interval = ScanInterval.Daily;
        else
            _settings.Interval = ScanInterval.Custom;

        if (int.TryParse(CustomMinutesBox.Text, out int minutes))
            _settings.CustomIntervalMinutes = Math.Max(5, minutes);

        _settings.NotifyOnComplete = NotifyCompleteCheck.IsChecked ?? true;
        _settings.NotifyOnScoreDrop = NotifyScoreDropCheck.IsChecked ?? true;
        _settings.NotifyOnNewFindings = NotifyNewFindingsCheck.IsChecked ?? true;

        // Collect selected modules
        var selectedModules = new List<string>();
        int totalModules = 0;
        foreach (var item in ModulesList.Items)
        {
            if (item is CheckBox cb)
            {
                totalModules++;
                if (cb.IsChecked == true && cb.Tag is string category)
                    selectedModules.Add(category);
            }
        }

        // If all modules are selected, store empty list (means "all")
        _settings.IncludedModules = selectedModules.Count == totalModules ? new() : selectedModules;

        _settings.Save();
        _scheduler?.UpdateSettings(_settings);
        _notificationService = new NotificationService(_settings);

        SavedText.Text = "✓ Settings saved";
        UpdateStatusDisplay();
    }

    private void UpdateStatusDisplay()
    {
        if (_settings.LastScanTime.HasValue)
        {
            var local = _settings.LastScanTime.Value.ToLocalTime();
            LastScanText.Text = $"Last scan: {local:yyyy-MM-dd HH:mm:ss}";
        }
        else
        {
            LastScanText.Text = "Last scan: Never";
        }

        if (_settings.Enabled && _settings.LastScanTime.HasValue)
        {
            var next = _settings.LastScanTime.Value + _settings.EffectiveInterval;
            NextScanText.Text = $"Next scan: {next.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
        }
        else if (_settings.Enabled)
        {
            NextScanText.Text = "Next scan: Starting soon...";
        }
        else
        {
            NextScanText.Text = "Next scan: Disabled";
        }

        LastScoreText.Text = _settings.LastScore.HasValue
            ? $"Last score: {_settings.LastScore}/100 ({SecurityScorer.GetGrade(_settings.LastScore.Value)})"
            : "Last score: —";
    }

    // Event handlers
    private void EnableToggle_Changed(object sender, RoutedEventArgs e)
    {
        var enabled = EnableToggle.IsChecked ?? false;
        IntervalSection.Opacity = enabled ? 1.0 : 0.5;
        IntervalSection.IsEnabled = enabled;
        SaveSettings();
    }

    private void Interval_Changed(object sender, RoutedEventArgs e)
    {
        CustomIntervalPanel.Visibility = IntervalCustom.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        SaveSettings();
    }

    private void CustomMinutes_Changed(object sender, TextChangedEventArgs e)
    {
        SaveSettings();
    }

    private void Notification_Changed(object sender, RoutedEventArgs e)
    {
        SaveSettings();
    }

    private void Module_Changed(object sender, RoutedEventArgs e)
    {
        SaveSettings();
    }

    private async void ScanNow_Click(object sender, RoutedEventArgs e)
    {
        if (_scheduler == null)
        {
            // Create a one-off scheduler
            var engine = new AuditEngine();
            _scheduler = new ScanScheduler(engine, _settings);
            SetScheduler(_scheduler);
        }

        ScanNowButton.IsEnabled = false;
        ScanStatusText.Text = "Starting scan...";

        await _scheduler.RunScanNowAsync();
    }

    private void TestNotification_Click(object sender, RoutedEventArgs e)
    {
        var testReport = new SecurityReport
        {
            SecurityScore = 72,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new()
        };

        var testArgs = new ScanCompletedEventArgs
        {
            Report = testReport,
            PreviousScore = 85,
            IsScheduled = true
        };

        var sender2 = new WindowsToastSender();
        sender2.ShowToast(
            NotificationService.BuildTitle(testArgs),
            NotificationService.BuildBody(testArgs),
            ToastUrgency.Normal);

        SavedText.Text = "🔔 Test notification sent!";
    }
}
