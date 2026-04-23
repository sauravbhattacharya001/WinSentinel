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

    /// <summary>Human-readable text describing the current agent connection state (e.g. "Running", "Stopped").</summary>
    private string _agentStatusText = "Unknown";
    /// <inheritdoc cref="_agentStatusText"/>
    public string AgentStatusText { get => _agentStatusText; set { _agentStatusText = value; Notify(); } }

    /// <summary>Emoji icon reflecting the agent connection state (🟢 / 🟡 / 🔴).</summary>
    private string _agentStatusIcon = "⚪";
    /// <inheritdoc cref="_agentStatusIcon"/>
    public string AgentStatusIcon { get => _agentStatusIcon; set { _agentStatusIcon = value; Notify(); } }

    /// <summary>Hex colour bound to the agent status indicator.</summary>
    private string _agentStatusColor = "#666666";
    /// <inheritdoc cref="_agentStatusColor"/>
    public string AgentStatusColor { get => _agentStatusColor; set { _agentStatusColor = value; Notify(); } }

    /// <summary>Formatted uptime string (e.g. "Running for 2h 14m").</summary>
    private string _uptimeText = "—";
    /// <inheritdoc cref="_uptimeText"/>
    public string UptimeText { get => _uptimeText; set { _uptimeText = value; Notify(); } }

    /// <summary>Latest audit security score (0–100, or -1 when no audit has run).</summary>
    private int _securityScore = -1;
    /// <inheritdoc cref="_securityScore"/>
    public int SecurityScore { get => _securityScore; set { _securityScore = value; Notify(); Notify(nameof(SecurityScoreDisplay)); Notify(nameof(HasScore)); } }

    /// <summary>Display-ready score string, falling back to "—" when unavailable.</summary>
    public string SecurityScoreDisplay => SecurityScore >= 0 ? SecurityScore.ToString() : "—";
    /// <summary>Returns <c>true</c> once at least one audit score has been recorded.</summary>
    public bool HasScore => SecurityScore >= 0;

    /// <summary>Letter grade derived from the security score (A+ / A / B / C / D / F).</summary>
    private string _securityGrade = "—";
    /// <inheritdoc cref="_securityGrade"/>
    public string SecurityGrade { get => _securityGrade; set { _securityGrade = value; Notify(); } }

    /// <summary>Hex colour mapped to the current score range (green → red).</summary>
    private string _scoreColor = "#666666";
    /// <inheritdoc cref="_scoreColor"/>
    public string ScoreColor { get => _scoreColor; set { _scoreColor = value; Notify(); } }

    /// <summary>Arrow character indicating score direction over the last 30 days (↑ / → / ↓).</summary>
    private string _scoreTrendArrow = "";
    /// <inheritdoc cref="_scoreTrendArrow"/>
    public string ScoreTrendArrow { get => _scoreTrendArrow; set { _scoreTrendArrow = value; Notify(); } }

    /// <summary>Short label describing the trend (e.g. "+4 improving", "stable").</summary>
    private string _scoreTrendText = "";
    /// <inheritdoc cref="_scoreTrendText"/>
    public string ScoreTrendText { get => _scoreTrendText; set { _scoreTrendText = value; Notify(); } }

    /// <summary>Hex colour for the trend label (green when improving, red when declining).</summary>
    private string _scoreTrendColor = "#888888";
    /// <inheritdoc cref="_scoreTrendColor"/>
    public string ScoreTrendColor { get => _scoreTrendColor; set { _scoreTrendColor = value; Notify(); } }

    /// <summary>Whether the IPC pipe to the agent process is currently established.</summary>
    private bool _isConnected;
    /// <inheritdoc cref="_isConnected"/>
    public bool IsConnected { get => _isConnected; set { _isConnected = value; Notify(); Notify(nameof(IsDisconnected)); } }

    /// <summary>Inverse of <see cref="IsConnected"/> for XAML visibility binding.</summary>
    public bool IsDisconnected => !IsConnected;

    /// <summary>Indicates an audit scan is currently in progress.</summary>
    private bool _isScanRunning;
    /// <inheritdoc cref="_isScanRunning"/>
    public bool IsScanRunning { get => _isScanRunning; set { _isScanRunning = value; Notify(); Notify(nameof(CanRunAudit)); } }

    /// <summary>Guard property for the Run Audit button — disabled while a scan is active.</summary>
    public bool CanRunAudit => !IsScanRunning;

    /// <summary>True when every agent monitor module has been paused by the user.</summary>
    private bool _allMonitorsPaused;
    /// <inheritdoc cref="_allMonitorsPaused"/>
    public bool AllMonitorsPaused { get => _allMonitorsPaused; set { _allMonitorsPaused = value; Notify(); Notify(nameof(PauseResumeText)); } }

    /// <summary>Button label that toggles between "Pause All" and "Resume All".</summary>
    public string PauseResumeText => AllMonitorsPaused ? "▶ Resume All" : "⏸ Pause All";

    /// <summary>Semantic version string reported by the running agent process.</summary>
    private string _agentVersion = "";
    /// <inheritdoc cref="_agentVersion"/>
    public string AgentVersion { get => _agentVersion; set { _agentVersion = value; Notify(); } }

    // ══════════════════════════════════════════
    //  Monitor Status Cards
    // ══════════════════════════════════════════

    /// <summary>Live collection of per-module status cards displayed in the monitor grid.</summary>
    public ObservableCollection<MonitorCardViewModel> MonitorCards { get; } = new();

    // ══════════════════════════════════════════
    //  Threat Summary (last 24h)
    // ══════════════════════════════════════════

    /// <summary>Number of Critical-severity threats detected in the last 24 hours.</summary>
    private int _criticalCount;
    /// <inheritdoc cref="_criticalCount"/>
    public int CriticalCount { get => _criticalCount; set { _criticalCount = value; Notify(); } }

    /// <summary>Number of High-severity threats in the last 24 hours.</summary>
    private int _highCount;
    /// <inheritdoc cref="_highCount"/>
    public int HighCount { get => _highCount; set { _highCount = value; Notify(); } }

    /// <summary>Number of Medium/Warning-severity threats in the last 24 hours.</summary>
    private int _mediumCount;
    /// <inheritdoc cref="_mediumCount"/>
    public int MediumCount { get => _mediumCount; set { _mediumCount = value; Notify(); } }

    /// <summary>Number of Low/Info-severity threats in the last 24 hours.</summary>
    private int _lowCount;
    /// <inheritdoc cref="_lowCount"/>
    public int LowCount { get => _lowCount; set { _lowCount = value; Notify(); } }

    /// <summary>Rolling list of the 10 most recent threats for the summary panel.</summary>
    public ObservableCollection<ThreatSummaryItem> RecentThreats { get; } = new();

    // ══════════════════════════════════════════
    //  Actions Taken
    // ══════════════════════════════════════════

    /// <summary>Count of automated remediation actions taken in the last 24 hours.</summary>
    private int _autoFixesToday;
    /// <inheritdoc cref="_autoFixesToday"/>
    public int AutoFixesToday { get => _autoFixesToday; set { _autoFixesToday = value; Notify(); } }

    /// <summary>Human-readable description of the most recent auto-fix action.</summary>
    private string _lastActionText = "No actions taken yet";
    /// <inheritdoc cref="_lastActionText"/>
    public string LastActionText { get => _lastActionText; set { _lastActionText = value; Notify(); } }

    // ══════════════════════════════════════════
    //  Agent Timeline
    // ══════════════════════════════════════════

    /// <summary>Chronological activity log entries displayed in the dashboard timeline.</summary>
    public ObservableCollection<TimelineEntry> TimelineEntries { get; } = new();

    // ══════════════════════════════════════════
    //  Setup & Lifecycle
    // ══════════════════════════════════════════

    /// <summary>
    /// Binds the dashboard to a live agent connection, wiring event handlers
    /// for status updates, threat notifications, and audit completions.
    /// </summary>
    /// <param name="connection">The IPC connection service to observe.</param>
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

            TimelineEntries.Add(CreateThreatTimelineEntry(time, threat.Severity, threat.Title));

            // Auto-fix action entry
            if (threat.ResponseTaken != null)
            {
                TimelineEntries.Add(CreateActionTimelineEntry(time, threat.ResponseTaken));
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

            TimelineEntries.Add(CreateThreatTimelineEntry(time, threat.Severity, threat.Title));

            if (threat.ResponseTaken != null)
            {
                TimelineEntries.Add(CreateActionTimelineEntry(time, threat.ResponseTaken));
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

    /// <summary>
    /// Triggers an on-demand full security audit via the connected agent.
    /// No-ops when disconnected or when a scan is already in progress.
    /// </summary>
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

    /// <summary>Disconnects and re-establishes the IPC connection to the agent.</summary>
    public async Task ReconnectAsync()
    {
        if (_agentConnection == null) return;
        _agentConnection.Disconnect();
        await _agentConnection.ConnectAsync();
    }

    // ══════════════════════════════════════════
    //  Severity helpers (DRY: used by RebuildTimeline,
    //  OnThreatReceived, and ThreatSummaryItem)
    // ══════════════════════════════════════════

    internal static string SeverityToIcon(string severity) => severity switch
    {
        "Critical" => "🔴",
        "High" => "🟠",
        "Medium" or "Warning" => "⚠️",
        _ => "🔵"
    };

    internal static TimelineEntryType SeverityToEntryType(string severity) => severity switch
    {
        "Critical" => TimelineEntryType.Critical,
        "High" => TimelineEntryType.High,
        "Medium" or "Warning" => TimelineEntryType.Warning,
        _ => TimelineEntryType.Info
    };

    private static TimelineEntry CreateThreatTimelineEntry(string time, string severity, string title)
        => new()
        {
            Time = time,
            Icon = SeverityToIcon(severity),
            Description = $"[{severity}] {title}",
            EntryType = SeverityToEntryType(severity)
        };

    private static TimelineEntry CreateActionTimelineEntry(string time, string responseTaken)
        => new()
        {
            Time = time,
            Icon = "🔧",
            Description = $"Auto-fix: {responseTaken}",
            EntryType = TimelineEntryType.Action
        };

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

    /// <summary>Stops the vitals polling timer and unwires all agent connection event handlers.</summary>
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
