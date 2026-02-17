using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using WinSentinel.App.Services;
using WinSentinel.Core.Services;

namespace WinSentinel.App.ViewModels;

/// <summary>
/// ViewModel for the live Agent Status Dashboard.
/// Binds to real-time data from the running agent via IPC.
/// </summary>
public class DashboardViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly Dispatcher _dispatcher;
    private AgentConnectionService? _agentConnection;
    private System.Timers.Timer? _vitalsTimer;
    private bool _disposed;
    public DashboardViewModel(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    // ══════════════════════════════════════════
    //  Agent Vitals
    // ══════════════════════════════════════════

    private string _agentStatusText = "Unknown";
    public string AgentStatusText { get => _agentStatusText; set { _agentStatusText = value; Notify(); } }

    private string _agentStatusIcon = "⚪";
    public string AgentStatusIcon { get => _agentStatusIcon; set { _agentStatusIcon = value; Notify(); } }

    private string _agentStatusColor = "#666666";
    public string AgentStatusColor { get => _agentStatusColor; set { _agentStatusColor = value; Notify(); } }

    private string _uptimeText = "—";
    public string UptimeText { get => _uptimeText; set { _uptimeText = value; Notify(); } }

    private int _securityScore = -1;
    public int SecurityScore { get => _securityScore; set { _securityScore = value; Notify(); Notify(nameof(SecurityScoreDisplay)); Notify(nameof(HasScore)); } }

    public string SecurityScoreDisplay => SecurityScore >= 0 ? SecurityScore.ToString() : "—";
    public bool HasScore => SecurityScore >= 0;

    private string _securityGrade = "—";
    public string SecurityGrade { get => _securityGrade; set { _securityGrade = value; Notify(); } }

    private string _scoreColor = "#666666";
    public string ScoreColor { get => _scoreColor; set { _scoreColor = value; Notify(); } }

    private string _scoreTrendArrow = "";
    public string ScoreTrendArrow { get => _scoreTrendArrow; set { _scoreTrendArrow = value; Notify(); } }

    private string _scoreTrendText = "";
    public string ScoreTrendText { get => _scoreTrendText; set { _scoreTrendText = value; Notify(); } }

    private string _scoreTrendColor = "#888888";
    public string ScoreTrendColor { get => _scoreTrendColor; set { _scoreTrendColor = value; Notify(); } }

    private bool _isConnected;
    public bool IsConnected { get => _isConnected; set { _isConnected = value; Notify(); Notify(nameof(IsDisconnected)); } }

    public bool IsDisconnected => !IsConnected;

    private bool _isScanRunning;
    public bool IsScanRunning { get => _isScanRunning; set { _isScanRunning = value; Notify(); Notify(nameof(CanRunAudit)); } }

    public bool CanRunAudit => !IsScanRunning;

    private bool _allMonitorsPaused;
    public bool AllMonitorsPaused { get => _allMonitorsPaused; set { _allMonitorsPaused = value; Notify(); Notify(nameof(PauseResumeText)); } }

    public string PauseResumeText => AllMonitorsPaused ? "▶ Resume All" : "⏸ Pause All";

    private string _agentVersion = "";
    public string AgentVersion { get => _agentVersion; set { _agentVersion = value; Notify(); } }

    // ══════════════════════════════════════════
    //  Monitor Status Cards
    // ══════════════════════════════════════════

    public ObservableCollection<MonitorCardViewModel> MonitorCards { get; } = new();

    // ══════════════════════════════════════════
    //  Threat Summary (last 24h)
    // ══════════════════════════════════════════

    private int _criticalCount;
    public int CriticalCount { get => _criticalCount; set { _criticalCount = value; Notify(); } }

    private int _highCount;
    public int HighCount { get => _highCount; set { _highCount = value; Notify(); } }

    private int _mediumCount;
    public int MediumCount { get => _mediumCount; set { _mediumCount = value; Notify(); } }

    private int _lowCount;
    public int LowCount { get => _lowCount; set { _lowCount = value; Notify(); } }

    public ObservableCollection<ThreatSummaryItem> RecentThreats { get; } = new();

    // ══════════════════════════════════════════
    //  Actions Taken
    // ══════════════════════════════════════════

    private int _autoFixesToday;
    public int AutoFixesToday { get => _autoFixesToday; set { _autoFixesToday = value; Notify(); } }

    private string _lastActionText = "No actions taken yet";
    public string LastActionText { get => _lastActionText; set { _lastActionText = value; Notify(); } }

    // ══════════════════════════════════════════
    //  Agent Timeline
    // ══════════════════════════════════════════

    public ObservableCollection<TimelineEntry> TimelineEntries { get; } = new();

    // ══════════════════════════════════════════
    //  Setup & Lifecycle
    // ══════════════════════════════════════════

    public void SetAgentConnection(AgentConnectionService connection)
    {
        // Unwire previous
        if (_agentConnection != null)
        {
            _agentConnection.StatusChanged -= OnConnectionStatusChanged;
            _agentConnection.AgentStatusUpdated -= OnAgentStatusUpdated;
            _agentConnection.ThreatReceived -= OnThreatReceived;
            _agentConnection.AuditCompleted -= OnAuditCompleted;
        }

        _agentConnection = connection;

        // Wire events
        _agentConnection.StatusChanged += OnConnectionStatusChanged;
        _agentConnection.AgentStatusUpdated += OnAgentStatusUpdated;
        _agentConnection.ThreatReceived += OnThreatReceived;
        _agentConnection.AuditCompleted += OnAuditCompleted;

        // Set initial state
        UpdateConnectionStatus(_agentConnection.Status);

        // Start polling vitals every 5 seconds
        StartVitalsTimer();

        // Load initial data
        _ = LoadInitialDataAsync();
    }

    private void StartVitalsTimer()
    {
        StopVitalsTimer();
        _vitalsTimer = new System.Timers.Timer(5000);
        _vitalsTimer.Elapsed += async (_, _) => await RefreshVitalsAsync();
        _vitalsTimer.AutoReset = true;
        _vitalsTimer.Start();
    }

    private void StopVitalsTimer()
    {
        _vitalsTimer?.Stop();
        _vitalsTimer?.Dispose();
        _vitalsTimer = null;
    }

    private async Task LoadInitialDataAsync()
    {
        await RefreshVitalsAsync();
        await LoadHistoricalThreatsAsync();
        LoadScoreTrend();
    }

    // ══════════════════════════════════════════
    //  Data Refresh
    // ══════════════════════════════════════════

    private async Task RefreshVitalsAsync()
    {
        if (_agentConnection == null || !_agentConnection.IsConnected) return;

        try
        {
            await _agentConnection.RefreshStatusAsync();
        }
        catch { /* Best effort */ }
    }

    private async Task LoadHistoricalThreatsAsync()
    {
        if (_agentConnection == null || !_agentConnection.IsConnected) return;

        try
        {
            var threats = await _agentConnection.GetHistoricalThreatsAsync();
            _dispatcher.Invoke(() =>
            {
                RecentThreats.Clear();
                var last24h = threats
                    .Where(t => t.Timestamp > DateTimeOffset.UtcNow.AddHours(-24))
                    .OrderByDescending(t => t.Timestamp)
                    .Take(10);

                foreach (var threat in last24h)
                {
                    RecentThreats.Add(new ThreatSummaryItem(threat));
                }

                // Update severity counts
                var all24h = threats.Where(t => t.Timestamp > DateTimeOffset.UtcNow.AddHours(-24)).ToList();
                CriticalCount = all24h.Count(t => t.Severity == "Critical");
                HighCount = all24h.Count(t => t.Severity == "High");
                MediumCount = all24h.Count(t => t.Severity == "Medium" || t.Severity == "Warning");
                LowCount = all24h.Count(t => t.Severity == "Low" || t.Severity == "Info");

                // Actions taken
                AutoFixesToday = all24h.Count(t =>
                    t.ResponseTaken?.Contains("Fix", StringComparison.OrdinalIgnoreCase) == true ||
                    t.ResponseTaken?.Contains("Kill", StringComparison.OrdinalIgnoreCase) == true ||
                    t.ResponseTaken?.Contains("Block", StringComparison.OrdinalIgnoreCase) == true);

                var lastAction = all24h.FirstOrDefault(t => t.ResponseTaken != null);
                if (lastAction != null)
                {
                    var ago = FormatTimeAgo(lastAction.Timestamp);
                    LastActionText = $"{lastAction.ResponseTaken}: {lastAction.Title} ({ago})";
                }

                // Build timeline from threats
                RebuildTimeline(threats);
            });
        }
        catch { /* Best effort */ }
    }

    private void LoadScoreTrend()
    {
        try
        {
            var historyService = new AuditHistoryService();
            var trend = historyService.GetTrend(30);

            if (trend.TotalScans > 0 && trend.PreviousScore.HasValue)
            {
                _dispatcher.Invoke(() =>
                {
                    var change = trend.ScoreChange;
                    if (change > 0)
                    {
                        ScoreTrendArrow = "↑";
                        ScoreTrendText = $"+{change} improving";
                        ScoreTrendColor = "#4CAF50";
                    }
                    else if (change < 0)
                    {
                        ScoreTrendArrow = "↓";
                        ScoreTrendText = $"{change} declining";
                        ScoreTrendColor = "#F44336";
                    }
                    else
                    {
                        ScoreTrendArrow = "→";
                        ScoreTrendText = "stable";
                        ScoreTrendColor = "#888888";
                    }
                });
            }
        }
        catch { /* Score history not available */ }
    }

    private void RebuildTimeline(List<IpcThreatEvent> threats)
    {
        TimelineEntries.Clear();

        // Add agent-started entry
        if (IsConnected)
        {
            TimelineEntries.Add(new TimelineEntry
            {
                Time = "—",
                Icon = "🚀",
                Description = "Agent started",
                EntryType = TimelineEntryType.Info
            });

            TimelineEntries.Add(new TimelineEntry
            {
                Time = "—",
                Icon = "👁️",
                Description = $"{MonitorCards.Count} monitors active",
                EntryType = TimelineEntryType.Info
            });
        }

        // Add threat and action entries from today
        var today = DateTimeOffset.UtcNow.Date;
        var todayThreats = threats
            .Where(t => t.Timestamp.UtcDateTime.Date == today)
            .OrderBy(t => t.Timestamp)
            .ToList();

        foreach (var threat in todayThreats)
        {
            var time = threat.Timestamp.ToLocalTime().ToString("HH:mm");

            // Threat detection entry
            var icon = threat.Severity switch
            {
                "Critical" => "🔴",
                "High" => "🟠",
                "Medium" or "Warning" => "⚠️",
                _ => "🔵"
            };

            var entryType = threat.Severity switch
            {
                "Critical" => TimelineEntryType.Critical,
                "High" => TimelineEntryType.High,
                "Medium" or "Warning" => TimelineEntryType.Warning,
                _ => TimelineEntryType.Info
            };

            TimelineEntries.Add(new TimelineEntry
            {
                Time = time,
                Icon = icon,
                Description = $"[{threat.Severity}] {threat.Title}",
                EntryType = entryType
            });

            // Auto-fix action entry
            if (threat.ResponseTaken != null)
            {
                TimelineEntries.Add(new TimelineEntry
                {
                    Time = time,
                    Icon = "🔧",
                    Description = $"Auto-fix: {threat.ResponseTaken}",
                    EntryType = TimelineEntryType.Action
                });
            }
        }

        // Add audit completed if score is available
        if (SecurityScore >= 0)
        {
            TimelineEntries.Add(new TimelineEntry
            {
                Time = "—",
                Icon = "📊",
                Description = $"Audit completed — Score: {SecurityScore}/100 ({SecurityGrade})",
                EntryType = TimelineEntryType.Info
            });
        }
    }

    // ══════════════════════════════════════════
    //  Event Handlers
    // ══════════════════════════════════════════

    private void OnConnectionStatusChanged(ConnectionStatus status)
    {
        _dispatcher.InvokeAsync(() => UpdateConnectionStatus(status));
    }

    private void UpdateConnectionStatus(ConnectionStatus status)
    {
        IsConnected = status == ConnectionStatus.Connected;

        switch (status)
        {
            case ConnectionStatus.Connected:
                AgentStatusText = "Running";
                AgentStatusIcon = "🟢";
                AgentStatusColor = "#4CAF50";
                break;
            case ConnectionStatus.Connecting:
                AgentStatusText = "Starting";
                AgentStatusIcon = "🟡";
                AgentStatusColor = "#FFC107";
                break;
            default:
                AgentStatusText = "Stopped";
                AgentStatusIcon = "🔴";
                AgentStatusColor = "#F44336";
                break;
        }
    }

    private void OnAgentStatusUpdated(IpcAgentStatus status)
    {
        _dispatcher.InvokeAsync(() =>
        {
            UptimeText = $"Running for {status.UptimeFormatted}";
            IsScanRunning = status.IsScanRunning;
            AgentVersion = status.Version;

            if (status.LastScanScore.HasValue)
            {
                SecurityScore = status.LastScanScore.Value;
                SecurityGrade = SecurityScorer.GetGrade(status.LastScanScore.Value);
                ScoreColor = SecurityScorer.GetScoreColor(status.LastScanScore.Value);
            }

            // Update monitor cards
            UpdateMonitorCards(status);
        });
    }

    private void UpdateMonitorCards(IpcAgentStatus status)
    {
        // Known modules and their display names
        var moduleInfo = new Dictionary<string, (string DisplayName, string Icon)>
        {
            ["ProcessMonitor"] = ("Process Monitor", "⚙️"),
            ["FileSystemMonitor"] = ("File System Monitor", "📂"),
            ["EventLogMonitor"] = ("Event Log Monitor", "📋"),
            ["ScheduledAudit"] = ("Scheduled Audit", "🔍"),
        };

        // Track which modules we've seen
        var existingModules = MonitorCards.ToDictionary(m => m.ModuleName);

        foreach (var moduleName in status.ActiveModules)
        {
            var (displayName, icon) = moduleInfo.TryGetValue(moduleName, out var info)
                ? info
                : (moduleName, "📦");

            if (existingModules.TryGetValue(moduleName, out var existing))
            {
                existing.Status = "Active";
                existing.StatusColor = "#4CAF50";
                existing.LastEventTime = DateTime.Now.ToString("HH:mm:ss");
            }
            else
            {
                MonitorCards.Add(new MonitorCardViewModel
                {
                    ModuleName = moduleName,
                    DisplayName = displayName,
                    Icon = icon,
                    Status = "Active",
                    StatusColor = "#4CAF50",
                    EventsDetected = 0,
                    LastEventTime = "—"
                });
            }
        }

        // Mark inactive modules
        foreach (var card in MonitorCards)
        {
            if (!status.ActiveModules.Contains(card.ModuleName))
            {
                card.Status = "Paused";
                card.StatusColor = "#FFC107";
            }
        }
    }

    private void OnThreatReceived(IpcThreatEvent threat)
    {
        _dispatcher.InvokeAsync(() =>
        {
            // Update severity counts
            switch (threat.Severity)
            {
                case "Critical": CriticalCount++; break;
                case "High": HighCount++; break;
                case "Medium": case "Warning": MediumCount++; break;
                default: LowCount++; break;
            }

            // Add to recent threats
            var item = new ThreatSummaryItem(threat);
            RecentThreats.Insert(0, item);
            while (RecentThreats.Count > 10) RecentThreats.RemoveAt(RecentThreats.Count - 1);

            // Update corresponding monitor card
            var card = MonitorCards.FirstOrDefault(m => m.ModuleName == threat.Source);
            if (card != null)
            {
                card.EventsDetected++;
                card.LastEventTime = threat.Timestamp.ToLocalTime().ToString("HH:mm:ss");
            }

            // Update actions if auto-fixed
            if (threat.ResponseTaken != null)
            {
                AutoFixesToday++;
                var ago = FormatTimeAgo(threat.Timestamp);
                LastActionText = $"{threat.ResponseTaken}: {threat.Title} ({ago})";
            }

            // Add to timeline
            var time = threat.Timestamp.ToLocalTime().ToString("HH:mm");
            var icon = threat.Severity switch
            {
                "Critical" => "🔴",
                "High" => "🟠",
                "Medium" or "Warning" => "⚠️",
                _ => "🔵"
            };

            TimelineEntries.Add(new TimelineEntry
            {
                Time = time,
                Icon = icon,
                Description = $"[{threat.Severity}] {threat.Title}",
                EntryType = threat.Severity == "Critical" ? TimelineEntryType.Critical :
                           threat.Severity == "High" ? TimelineEntryType.High :
                           TimelineEntryType.Warning
            });

            if (threat.ResponseTaken != null)
            {
                TimelineEntries.Add(new TimelineEntry
                {
                    Time = time,
                    Icon = "🔧",
                    Description = $"Auto-fix: {threat.ResponseTaken}",
                    EntryType = TimelineEntryType.Action
                });
            }
        });
    }

    private void OnAuditCompleted(int score)
    {
        _dispatcher.InvokeAsync(() =>
        {
            SecurityScore = score;
            SecurityGrade = SecurityScorer.GetGrade(score);
            ScoreColor = SecurityScorer.GetScoreColor(score);

            TimelineEntries.Add(new TimelineEntry
            {
                Time = DateTime.Now.ToString("HH:mm"),
                Icon = "📊",
                Description = $"Audit completed — Score: {score}/100 ({SecurityGrade})",
                EntryType = TimelineEntryType.Info
            });

            // Reload trend data
            LoadScoreTrend();
        });
    }

    // ══════════════════════════════════════════
    //  Commands
    // ══════════════════════════════════════════

    public async Task RunFullAuditAsync()
    {
        if (_agentConnection == null || !IsConnected || IsScanRunning) return;

        IsScanRunning = true;
        try
        {
            await Task.Run(async () =>
            {
                var client = _agentConnection.Client;
                await client.RunAuditAsync();
            });
        }
        catch
        {
            IsScanRunning = false;
        }
    }

    public async Task ReconnectAsync()
    {
        if (_agentConnection == null) return;
        _agentConnection.Disconnect();
        await _agentConnection.ConnectAsync();
    }

    // ══════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════

    private static string FormatTimeAgo(DateTimeOffset timestamp)
    {
        var elapsed = DateTimeOffset.Now - timestamp.ToLocalTime();
        if (elapsed.TotalMinutes < 1) return "just now";
        if (elapsed.TotalMinutes < 60) return $"{(int)elapsed.TotalMinutes} min ago";
        if (elapsed.TotalHours < 24) return $"{(int)elapsed.TotalHours}h ago";
        return $"{(int)elapsed.TotalDays}d ago";
    }

    // ══════════════════════════════════════════
    //  INotifyPropertyChanged
    // ══════════════════════════════════════════

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    // ══════════════════════════════════════════
    //  IDisposable
    // ══════════════════════════════════════════

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopVitalsTimer();

        if (_agentConnection != null)
        {
            _agentConnection.StatusChanged -= OnConnectionStatusChanged;
            _agentConnection.AgentStatusUpdated -= OnAgentStatusUpdated;
            _agentConnection.ThreatReceived -= OnThreatReceived;
            _agentConnection.AuditCompleted -= OnAuditCompleted;
        }

        GC.SuppressFinalize(this);
    }
}

// ══════════════════════════════════════════
//  Supporting ViewModels
// ══════════════════════════════════════════

/// <summary>Monitor status card data.</summary>
public class MonitorCardViewModel : INotifyPropertyChanged
{
    public string ModuleName { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Icon { get; set; } = "📦";

    private string _status = "Unknown";
    public string Status { get => _status; set { _status = value; Notify(); } }

    private string _statusColor = "#666666";
    public string StatusColor { get => _statusColor; set { _statusColor = value; Notify(); } }

    private int _eventsDetected;
    public int EventsDetected { get => _eventsDetected; set { _eventsDetected = value; Notify(); } }

    private string _lastEventTime = "—";
    public string LastEventTime { get => _lastEventTime; set { _lastEventTime = value; Notify(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Condensed threat item for the summary view.</summary>
public class ThreatSummaryItem
{
    public ThreatSummaryItem(IpcThreatEvent threat)
    {
        Id = threat.Id;
        Time = threat.Timestamp.ToLocalTime().ToString("HH:mm");
        Severity = threat.Severity;
        Title = threat.Title;
        Source = threat.Source;
        WasAutoFixed = threat.ResponseTaken != null;
        ResponseTaken = threat.ResponseTaken;

        SeverityIcon = Severity switch
        {
            "Critical" => "🔴",
            "High" => "🟠",
            "Medium" or "Warning" => "🟡",
            _ => "🔵"
        };

        SeverityColor = Severity switch
        {
            "Critical" => "#F44336",
            "High" => "#FF9800",
            "Medium" or "Warning" => "#FFC107",
            _ => "#2196F3"
        };
    }

    public string Id { get; }
    public string Time { get; }
    public string Severity { get; }
    public string SeverityIcon { get; }
    public string SeverityColor { get; }
    public string Title { get; }
    public string Source { get; }
    public bool WasAutoFixed { get; }
    public string? ResponseTaken { get; }
}

/// <summary>Timeline entry for the activity log.</summary>
public class TimelineEntry
{
    public string Time { get; set; } = "";
    public string Icon { get; set; } = "";
    public string Description { get; set; } = "";
    public TimelineEntryType EntryType { get; set; }

    public string EntryColor => EntryType switch
    {
        TimelineEntryType.Critical => "#F44336",
        TimelineEntryType.High => "#FF9800",
        TimelineEntryType.Warning => "#FFC107",
        TimelineEntryType.Action => "#4CAF50",
        TimelineEntryType.Info => "#AAAACC",
        _ => "#AAAACC"
    };
}

public enum TimelineEntryType
{
    Info,
    Warning,
    High,
    Critical,
    Action
}
