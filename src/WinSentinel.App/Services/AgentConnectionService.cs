using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using WinSentinel.Core.Services;

namespace WinSentinel.App.Services;

/// <summary>
/// Manages the persistent connection to the WinSentinel Agent via IPC.
/// Handles connection lifecycle, reconnection, event subscription, and status tracking.
/// </summary>
public class AgentConnectionService : INotifyPropertyChanged, IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly IpcClient _client;
    private CancellationTokenSource? _reconnectCts;
    private bool _disposed;
    private System.Timers.Timer? _statusTimer;

    public AgentConnectionService(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        _client = new IpcClient();

        // Wire up events
        _client.ThreatDetected += OnThreatDetected;
        _client.Disconnected += OnDisconnected;
        _client.AgentShutdown += OnAgentShutdown;
        _client.AuditCompleted += OnAuditCompleted;
    }

    // ── Events ──

    /// <summary>Fired when a threat event is received from the agent.</summary>
    public event Action<IpcThreatEvent>? ThreatReceived;

    /// <summary>Fired when connection status changes.</summary>
    public event Action<ConnectionStatus>? StatusChanged;

    /// <summary>Fired when agent status is refreshed.</summary>
    public event Action<IpcAgentStatus>? AgentStatusUpdated;

    /// <summary>Fired when an audit completes.</summary>
    public event Action<int>? AuditCompleted;

    // ── Properties ──

    private ConnectionStatus _status = ConnectionStatus.Disconnected;
    public ConnectionStatus Status
    {
        get => _status;
        private set
        {
            if (_status == value) return;
            _status = value;
            _dispatcher.InvokeAsync(() =>
            {
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(StatusIcon));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(ShowReconnect));
                StatusChanged?.Invoke(value);
            });
        }
    }

    public string StatusText => Status switch
    {
        ConnectionStatus.Connected => "Connected",
        ConnectionStatus.Connecting => "Connecting...",
        ConnectionStatus.Disconnected => "Disconnected",
        _ => "Unknown"
    };

    public string StatusIcon => Status switch
    {
        ConnectionStatus.Connected => "🟢",
        ConnectionStatus.Connecting => "🟡",
        ConnectionStatus.Disconnected => "🔴",
        _ => "⚪"
    };

    public bool IsConnected => Status == ConnectionStatus.Connected;
    public bool ShowReconnect => Status == ConnectionStatus.Disconnected;

    private string _agentUptime = "—";
    public string AgentUptime
    {
        get => _agentUptime;
        private set { _agentUptime = value; _dispatcher.InvokeAsync(() => OnPropertyChanged()); }
    }

    private int _activeMonitors;
    public int ActiveMonitors
    {
        get => _activeMonitors;
        private set { _activeMonitors = value; _dispatcher.InvokeAsync(() => OnPropertyChanged()); }
    }

    private int _threatsToday;
    public int ThreatsToday
    {
        get => _threatsToday;
        private set { _threatsToday = value; _dispatcher.InvokeAsync(() => OnPropertyChanged()); }
    }

    private string _lastScanTime = "Never";
    public string LastScanTime
    {
        get => _lastScanTime;
        private set { _lastScanTime = value; _dispatcher.InvokeAsync(() => OnPropertyChanged()); }
    }

    private int _unreadCriticalCount;
    public int UnreadCriticalCount
    {
        get => _unreadCriticalCount;
        set { _unreadCriticalCount = value; _dispatcher.InvokeAsync(() => OnPropertyChanged()); }
    }

    /// <summary>The underlying IPC client for direct operations.</summary>
    public IpcClient Client => _client;

    // ── Connection Management ──

    /// <summary>Start connecting to the agent. Will auto-reconnect on failure.</summary>
    public async Task ConnectAsync()
    {
        if (Status == ConnectionStatus.Connected || Status == ConnectionStatus.Connecting) return;

        Status = ConnectionStatus.Connecting;
        _reconnectCts?.Cancel();
        _reconnectCts = new CancellationTokenSource();

        try
        {
            var connected = await _client.ConnectAsync(_reconnectCts.Token);
            if (connected)
            {
                await _client.SubscribeAsync(_reconnectCts.Token);
                Status = ConnectionStatus.Connected;

                // Start periodic status polling
                StartStatusTimer();

                // Initial status fetch
                await RefreshStatusAsync();
            }
            else
            {
                Status = ConnectionStatus.Disconnected;
                ScheduleReconnect();
            }
        }
        catch
        {
            Status = ConnectionStatus.Disconnected;
            ScheduleReconnect();
        }
    }

    /// <summary>Disconnect from the agent.</summary>
    public void Disconnect()
    {
        _reconnectCts?.Cancel();
        StopStatusTimer();
        _client.Disconnect();
        Status = ConnectionStatus.Disconnected;
    }

    /// <summary>Fetch the latest agent status.</summary>
    public async Task RefreshStatusAsync()
    {
        if (!IsConnected) return;

        try
        {
            var status = await _client.GetStatusAsync();
            if (status != null)
            {
                AgentUptime = status.UptimeFormatted;
                ActiveMonitors = status.ActiveModules.Count;
                ThreatsToday = status.ThreatsDetectedToday;
                LastScanTime = status.LastScanTime?.ToLocalTime().ToString("HH:mm:ss") ?? "Never";

                AgentStatusUpdated?.Invoke(status);
            }
        }
        catch
        {
            // Status fetch failed — connection might be dying
        }
    }

    /// <summary>Fetch historical threats from the agent.</summary>
    public async Task<List<IpcThreatEvent>> GetHistoricalThreatsAsync()
    {
        if (!IsConnected) return [];

        try
        {
            return await _client.GetThreatsAsync();
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Request a fix execution via the agent.</summary>
    public async Task<IpcFixResult?> RunFixAsync(string fixCommand, string? title = null)
    {
        if (!IsConnected) return null;

        try
        {
            return await _client.RunFixAsync(fixCommand, title);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Send a chat message to the agent and get a rich response.</summary>
    public async Task<IpcChatResponse?> SendChatAsync(string message)
    {
        if (!IsConnected) return null;

        try
        {
            return await _client.SendChatAsync(message);
        }
        catch
        {
            return null;
        }
    }

    // ── Private Methods ──

    private void ScheduleReconnect()
    {
        if (_disposed) return;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(5000, _reconnectCts?.Token ?? CancellationToken.None);
                if (!_disposed && Status == ConnectionStatus.Disconnected)
                {
                    await ConnectAsync();
                }
            }
            catch (OperationCanceledException) { }
        });
    }

    private void StartStatusTimer()
    {
        StopStatusTimer();
        _statusTimer = new System.Timers.Timer(10000); // Every 10 seconds
        _statusTimer.Elapsed += async (_, _) => await RefreshStatusAsync();
        _statusTimer.AutoReset = true;
        _statusTimer.Start();
    }

    private void StopStatusTimer()
    {
        _statusTimer?.Stop();
        _statusTimer?.Dispose();
        _statusTimer = null;
    }

    private void OnThreatDetected(IpcThreatEvent threat)
    {
        ThreatsToday++;
        if (threat.Severity == "Critical")
            UnreadCriticalCount++;

        ThreatReceived?.Invoke(threat);
    }

    private void OnDisconnected()
    {
        StopStatusTimer();
        Status = ConnectionStatus.Disconnected;
        ScheduleReconnect();
    }

    private void OnAgentShutdown()
    {
        StopStatusTimer();
        Status = ConnectionStatus.Disconnected;
        ScheduleReconnect();
    }

    private void OnAuditCompleted(int score)
    {
        AuditCompleted?.Invoke(score);
        _ = RefreshStatusAsync();
    }

    // ── INotifyPropertyChanged ──

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    // ── IDisposable ──

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _reconnectCts?.Cancel();
        StopStatusTimer();
        _client.Dispose();
        _reconnectCts?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>Agent connection status.</summary>
public enum ConnectionStatus
{
    Disconnected,
    Connecting,
    Connected
}
