using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using WinSentinel.Core.Services;

namespace WinSentinel.App.ViewModels;

/// <summary>
/// ViewModel for the real-time threat feed page.
/// Manages threat events, filtering, stats, and auto-scroll behavior.
/// </summary>
public class ThreatFeedViewModel : INotifyPropertyChanged
{
    private readonly Dispatcher _dispatcher;

    public ThreatFeedViewModel(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    // ── Collections ──

    /// <summary>All received threat events (unfiltered).</summary>
    public ObservableCollection<ThreatItemViewModel> AllThreats { get; } = new();

    /// <summary>Filtered threat events for display.</summary>
    public ObservableCollection<ThreatItemViewModel> FilteredThreats { get; } = new();

    // ── Stats ──

    private int _criticalCount;
    public int CriticalCount { get => _criticalCount; set { _criticalCount = value; OnPropertyChanged(); } }

    private int _highCount;
    public int HighCount { get => _highCount; set { _highCount = value; OnPropertyChanged(); } }

    private int _mediumCount;
    public int MediumCount { get => _mediumCount; set { _mediumCount = value; OnPropertyChanged(); } }

    private int _lowCount;
    public int LowCount { get => _lowCount; set { _lowCount = value; OnPropertyChanged(); } }

    private int _autoFixedCount;
    public int AutoFixedCount { get => _autoFixedCount; set { _autoFixedCount = value; OnPropertyChanged(); } }

    private int _dismissedCount;
    public int DismissedCount { get => _dismissedCount; set { _dismissedCount = value; OnPropertyChanged(); } }

    private int _totalToday;
    public int TotalToday { get => _totalToday; set { _totalToday = value; OnPropertyChanged(); } }

    // ── Filters ──

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set { _searchText = value; OnPropertyChanged(); ApplyFilter(); }
    }

    private string _severityFilter = "All";
    public string SeverityFilter
    {
        get => _severityFilter;
        set { _severityFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    private string _moduleFilter = "All";
    public string ModuleFilter
    {
        get => _moduleFilter;
        set { _moduleFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    private string _timeFilter = "All";
    public string TimeFilter
    {
        get => _timeFilter;
        set { _timeFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    /// <summary>Available source modules for filtering.</summary>
    public ObservableCollection<string> AvailableModules { get; } = new() { "All" };

    // ── Auto-scroll ──

    private bool _autoScroll = true;
    public bool AutoScroll
    {
        get => _autoScroll;
        set { _autoScroll = value; OnPropertyChanged(); }
    }

    // ── Methods ──

    /// <summary>Add a new threat event from the agent.</summary>
    public void AddThreat(IpcThreatEvent ipcEvent)
    {
        _dispatcher.InvokeAsync(() =>
        {
            var item = new ThreatItemViewModel(ipcEvent);
            AllThreats.Insert(0, item);

            // Update available modules
            if (!string.IsNullOrEmpty(ipcEvent.Source) && !AvailableModules.Contains(ipcEvent.Source))
                AvailableModules.Add(ipcEvent.Source);

            UpdateStats();

            if (PassesFilter(item))
                FilteredThreats.Insert(0, item);
        });
    }

    /// <summary>Load historical threats from the agent.</summary>
    public void LoadThreats(IEnumerable<IpcThreatEvent> events)
    {
        _dispatcher.InvokeAsync(() =>
        {
            AllThreats.Clear();
            FilteredThreats.Clear();

            foreach (var e in events.OrderByDescending(t => t.Timestamp))
            {
                var item = new ThreatItemViewModel(e);
                AllThreats.Add(item);

                if (!string.IsNullOrEmpty(e.Source) && !AvailableModules.Contains(e.Source))
                    AvailableModules.Add(e.Source);
            }

            UpdateStats();
            ApplyFilter();
        });
    }

    /// <summary>Mark a threat as dismissed.</summary>
    public void DismissThreat(ThreatItemViewModel item)
    {
        item.IsDismissed = true;
        item.ResponseTaken = "Dismissed";
        DismissedCount++;
        OnPropertyChanged(nameof(DismissedCount));
    }

    /// <summary>Recalculate stats from all threats.</summary>
    public void UpdateStats()
    {
        var today = DateTimeOffset.Now.Date;
        var todayThreats = AllThreats.Where(t => t.Timestamp.Date == today).ToList();

        CriticalCount = todayThreats.Count(t => t.SeverityLevel == "Critical");
        HighCount = todayThreats.Count(t => t.SeverityLevel == "High");
        MediumCount = todayThreats.Count(t => t.SeverityLevel == "Medium" || t.SeverityLevel == "Warning");
        LowCount = todayThreats.Count(t => t.SeverityLevel == "Low" || t.SeverityLevel == "Info");
        AutoFixedCount = todayThreats.Count(t => t.ResponseTaken?.Contains("Fix", StringComparison.OrdinalIgnoreCase) == true);
        DismissedCount = todayThreats.Count(t => t.IsDismissed);
        TotalToday = todayThreats.Count;
    }

    /// <summary>Re-apply filters to the full collection.</summary>
    public void ApplyFilter()
    {
        FilteredThreats.Clear();
        foreach (var item in AllThreats)
        {
            if (PassesFilter(item))
                FilteredThreats.Add(item);
        }
    }

    private bool PassesFilter(ThreatItemViewModel item)
    {
        // Severity filter
        if (SeverityFilter != "All" && !string.Equals(item.SeverityLevel, SeverityFilter, StringComparison.OrdinalIgnoreCase))
            return false;

        // Module filter
        if (ModuleFilter != "All" && !string.Equals(item.Source, ModuleFilter, StringComparison.OrdinalIgnoreCase))
            return false;

        // Time filter
        if (TimeFilter != "All")
        {
            var now = DateTimeOffset.Now;
            var cutoff = TimeFilter switch
            {
                "Last Hour" => now.AddHours(-1),
                "Last 24h" => now.AddDays(-1),
                "Last 7 Days" => now.AddDays(-7),
                _ => DateTimeOffset.MinValue
            };
            if (item.Timestamp < cutoff) return false;
        }

        // Search text
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim();
            if (!item.Title.Contains(search, StringComparison.OrdinalIgnoreCase) &&
                !item.Description.Contains(search, StringComparison.OrdinalIgnoreCase) &&
                !item.Source.Contains(search, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    // ── INotifyPropertyChanged ──

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// ViewModel for a single threat event card.
/// </summary>
public class ThreatItemViewModel : INotifyPropertyChanged
{
    public ThreatItemViewModel(IpcThreatEvent e)
    {
        Id = e.Id;
        Timestamp = e.Timestamp.ToLocalTime();
        Source = e.Source;
        SeverityLevel = e.Severity;
        Title = e.Title;
        Description = e.Description;
        AutoFixable = e.AutoFixable;
        ResponseTaken = e.ResponseTaken;
        FixCommand = e.FixCommand;

        SeverityIcon = SeverityLevel switch
        {
            "Critical" => "🔴",
            "High" => "🟠",
            "Medium" or "Warning" => "🟡",
            "Low" => "🔵",
            "Info" => "🔵",
            _ => "🟢"
        };

        SeverityColor = SeverityLevel switch
        {
            "Critical" => "#F44336",
            "High" => "#FF9800",
            "Medium" or "Warning" => "#FFC107",
            "Low" => "#2196F3",
            "Info" => "#2196F3",
            _ => "#4CAF50"
        };

        IsAutoFixed = ResponseTaken?.Contains("Fix", StringComparison.OrdinalIgnoreCase) == true;
        CanFix = AutoFixable && !IsAutoFixed && !string.IsNullOrEmpty(FixCommand);
    }

    public string Id { get; }
    public DateTimeOffset Timestamp { get; }
    public string Source { get; }
    public string SeverityLevel { get; }
    public string SeverityIcon { get; }
    public string SeverityColor { get; }
    public string Title { get; }
    public string Description { get; }
    public bool AutoFixable { get; }
    public string? FixCommand { get; }

    public string TimestampFormatted => Timestamp.ToString("HH:mm:ss");
    public string TimestampFull => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");

    private string? _responseTaken;
    public string? ResponseTaken
    {
        get => _responseTaken;
        set { _responseTaken = value; OnPropertyChanged(); OnPropertyChanged(nameof(ResponseDisplay)); }
    }

    public string ResponseDisplay => ResponseTaken ?? "Logged";

    private bool _isDismissed;
    public bool IsDismissed
    {
        get => _isDismissed;
        set { _isDismissed = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanFix)); OnPropertyChanged(nameof(CanDismiss)); }
    }

    private bool _isExpanded;
    public bool IsExpanded
    {
        get => _isExpanded;
        set { _isExpanded = value; OnPropertyChanged(); }
    }

    public bool IsAutoFixed { get; private set; }

    private bool _canFix;
    public bool CanFix
    {
        get => _canFix && !IsDismissed;
        set { _canFix = value; OnPropertyChanged(); }
    }

    public bool CanDismiss => !IsDismissed;
    public bool CanUndo => IsAutoFixed;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
