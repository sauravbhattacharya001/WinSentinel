using System.Windows;
using System.Windows.Controls;
using WinSentinel.App.Services;
using WinSentinel.App.ViewModels;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Views;

/// <summary>
/// Real-time threat feed page — streams live security events from the WinSentinel Agent.
/// </summary>
public partial class ThreatFeedPage : Page
{
    private readonly ThreatFeedViewModel _vm;
    private AgentConnectionService? _agentService;
    private bool _userScrolledUp;

    public ThreatFeedPage()
    {
        InitializeComponent();
        _vm = new ThreatFeedViewModel(Dispatcher);
        _vm.PropertyChanged += (_, args) => UpdateStatsDisplay();

        Loaded += ThreatFeedPage_Loaded;
        Unloaded += ThreatFeedPage_Unloaded;
    }

    /// <summary>Set the agent connection service (injected from MainWindow).</summary>
    public void SetAgentService(AgentConnectionService service)
    {
        _agentService = service;
        _agentService.ThreatReceived += OnThreatReceived;
    }

    private async void ThreatFeedPage_Loaded(object sender, RoutedEventArgs e)
    {
        // Load historical threats
        if (_agentService != null)
        {
            var threats = await _agentService.GetHistoricalThreatsAsync();
            _vm.LoadThreats(threats);

            // Update module filter dropdown
            foreach (var module in _vm.AvailableModules)
            {
                if (module == "All") continue;
                var item = new ComboBoxItem { Content = module };
                ModuleCombo.Items.Add(item);
            }
        }

        ThreatList.ItemsSource = _vm.FilteredThreats;
        UpdateStatsDisplay();
        UpdateEmptyState();

        // Clear unread count when viewing
        if (_agentService != null)
            _agentService.UnreadCriticalCount = 0;
    }

    private void ThreatFeedPage_Unloaded(object sender, RoutedEventArgs e)
    {
        if (_agentService != null)
            _agentService.ThreatReceived -= OnThreatReceived;
    }

    private void OnThreatReceived(IpcThreatEvent threat)
    {
        Dispatcher.InvokeAsync(() =>
        {
            _vm.AddThreat(threat);
            UpdateStatsDisplay();
            UpdateEmptyState();

            // Auto-scroll to top (newest first) if user hasn't scrolled away
            if (!_userScrolledUp && ThreatScroller.VerticalOffset < 10)
            {
                ThreatScroller.ScrollToTop();
            }

            // Show toast for critical threats
            if (threat.Severity == "Critical")
            {
                ShowCriticalToast(threat);
            }
        });
    }

    // ── Filter Handlers ──

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _vm.SearchText = SearchBox.Text;
        UpdateEmptyState();
    }

    private void SeverityCombo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (SeverityCombo.SelectedItem is ComboBoxItem item)
        {
            var content = item.Content?.ToString() ?? "All";
            _vm.SeverityFilter = content.Contains("All") ? "All" : content;
            UpdateEmptyState();
        }
    }

    private void ModuleCombo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (ModuleCombo.SelectedItem is ComboBoxItem item)
        {
            var content = item.Content?.ToString() ?? "All";
            _vm.ModuleFilter = content.Contains("All") ? "All" : content;
            UpdateEmptyState();
        }
    }

    private void TimeCombo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (TimeCombo.SelectedItem is ComboBoxItem item)
        {
            var content = item.Content?.ToString() ?? "All";
            _vm.TimeFilter = content.Contains("All") ? "All" : content;
            UpdateEmptyState();
        }
    }

    private void ClearFilters_Click(object sender, RoutedEventArgs e)
    {
        SearchBox.Text = "";
        SeverityCombo.SelectedIndex = 0;
        ModuleCombo.SelectedIndex = 0;
        TimeCombo.SelectedIndex = 0;
        _vm.SearchText = "";
        _vm.SeverityFilter = "All";
        _vm.ModuleFilter = "All";
        _vm.TimeFilter = "All";
        UpdateEmptyState();
    }

    // ── Action Button Handlers ──

    private async void FixButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not ThreatItemViewModel item) return;
        if (_agentService == null || string.IsNullOrEmpty(item.FixCommand)) return;

        btn.IsEnabled = false;
        btn.Content = "⏳ Fixing...";

        var result = await _agentService.RunFixAsync(item.FixCommand, item.Title);
        if (result?.Success == true)
        {
            item.ResponseTaken = "Fixed (manual)";
            item.CanFix = false;
            _vm.UpdateStats();
            UpdateStatsDisplay();
        }
        else
        {
            btn.Content = "❌ Failed";
            await Task.Delay(2000);
            btn.Content = "🔧 Fix";
            btn.IsEnabled = true;
        }
    }

    private void DismissButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is ThreatItemViewModel item)
        {
            _vm.DismissThreat(item);
            UpdateStatsDisplay();
        }
    }

    private async void UndoButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is ThreatItemViewModel item)
        {
            // Undo is complex — for now, notify user
            MessageBox.Show(
                $"Undo is not yet implemented for: {item.Title}\n\nThe auto-fix action would need to be manually reversed.",
                "Undo Not Available",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        await Task.CompletedTask;
    }

    private void DetailsButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is ThreatItemViewModel item)
        {
            item.IsExpanded = !item.IsExpanded;
            btn.Content = item.IsExpanded ? "🔼 Hide" : "🔽 Details";
        }
    }

    private void IgnoreFutureButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is ThreatItemViewModel item)
        {
            var result = MessageBox.Show(
                $"Ignore future threats matching: '{item.Title}'?\n\nThis will suppress similar alerts from {item.Source}.",
                "Ignore Future Threats",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                item.ResponseTaken = "Ignored (user override)";
                item.IsDismissed = true;
            }
        }
    }

    // ── Auto-Scroll ──

    private void ThreatScroller_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        // Detect if user scrolled up (reading older events)
        if (e.VerticalChange < 0)
        {
            _userScrolledUp = true;
        }

        // Re-enable auto-scroll when user scrolls back to top
        if (ThreatScroller.VerticalOffset < 10)
        {
            _userScrolledUp = false;
        }
    }

    // ── Helpers ──

    private void UpdateStatsDisplay()
    {
        Dispatcher.InvokeAsync(() =>
        {
            StatTotal.Text = _vm.TotalToday.ToString();
            StatCritical.Text = _vm.CriticalCount.ToString();
            StatHigh.Text = _vm.HighCount.ToString();
            StatMedium.Text = _vm.MediumCount.ToString();
            StatLow.Text = _vm.LowCount.ToString();
            StatFixed.Text = _vm.AutoFixedCount.ToString();
            StatDismissed.Text = _vm.DismissedCount.ToString();
        });
    }

    private void UpdateEmptyState()
    {
        Dispatcher.InvokeAsync(() =>
        {
            EmptyState.Visibility = _vm.FilteredThreats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ThreatScroller.Visibility = _vm.FilteredThreats.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    private void ShowCriticalToast(IpcThreatEvent threat)
    {
        try
        {
            var sender = new WindowsToastSender();
            sender.ShowToast(
                $"🔴 CRITICAL: {threat.Title}",
                $"Source: {threat.Source}\n{threat.Description}",
                ToastUrgency.High);
        }
        catch
        {
            // Toast is best-effort
        }
    }

    /// <summary>Scroll to a specific threat by ID (for toast click navigation).</summary>
    public void ScrollToThreat(string threatId)
    {
        var item = _vm.FilteredThreats.FirstOrDefault(t => t.Id == threatId);
        if (item != null)
        {
            var index = _vm.FilteredThreats.IndexOf(item);
            // The ItemsControl doesn't support ScrollIntoView directly,
            // but we can scroll the parent ScrollViewer
            ThreatScroller.ScrollToTop();
        }
    }
}
