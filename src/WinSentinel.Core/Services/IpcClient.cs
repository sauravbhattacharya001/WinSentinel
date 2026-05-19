using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// IPC client for connecting to the WinSentinel Agent via named pipe.
/// Used by the WPF app to communicate with the running agent service.
/// </summary>
public class IpcClient : IDisposable
{
    private const string PipeName = "WinSentinel";
    private const int ConnectTimeoutMs = 3000;

    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private CancellationTokenSource? _eventCts;
    private Task? _eventLoop;
    private bool _disposed;
    private int _disconnectedFired;

    /// <summary>Whether we're currently connected to the agent.</summary>
    public bool IsConnected => _pipe?.IsConnected ?? false;

    /// <summary>Fired when a threat event is pushed from the agent.</summary>
    public event Action<IpcThreatEvent>? ThreatDetected;

    /// <summary>Fired when scan progress is pushed from the agent.</summary>
    public event Action<IpcScanProgress>? ScanProgressReceived;

    /// <summary>Fired when audit completed event is pushed.</summary>
    public event Action<int>? AuditCompleted;

    /// <summary>Fired when the agent is shutting down.</summary>
    public event Action? AgentShutdown;

    /// <summary>Fired when the connection is lost.</summary>
    public event Action? Disconnected;

    /// <summary>Try to connect to the agent service.</summary>
    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        try
        {
            Interlocked.Exchange(ref _disconnectedFired, 0);
            _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await _pipe.ConnectAsync(ConnectTimeoutMs, ct);

            _reader = new StreamReader(_pipe);
            _writer = new StreamWriter(_pipe) { AutoFlush = true };

            // Start event listener
            _eventCts = new CancellationTokenSource();
            _eventLoop = Task.Run(() => EventLoopAsync(_eventCts.Token));

            return true;
        }
        catch
        {
            Cleanup();
            return false;
        }
    }

    /// <summary>Disconnect from the agent.</summary>
    public void Disconnect()
    {
        _eventCts?.Cancel();
        Cleanup();
        FireDisconnected();
    }

    /// <summary>Ping the agent to check connectivity.</summary>
    public async Task<bool> PingAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await SendRequestAsync("Ping", ct: ct);
            return response?.Type == "Pong";
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Get the agent's current status.</summary>
    public async Task<IpcAgentStatus?> GetStatusAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("GetStatus", ct: ct);
        return response?.GetPayload<IpcAgentStatus>();
    }

    /// <summary>Request an immediate audit run.</summary>
    public async Task<bool> RunAuditAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("RunAudit", ct: ct);
        return response?.Type == "AuditStarted";
    }

    /// <summary>Get recent threat events.</summary>
    public async Task<List<IpcThreatEvent>> GetThreatsAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("GetThreats", ct: ct);
        return response?.GetPayload<List<IpcThreatEvent>>() ?? [];
    }

    /// <summary>Get the agent's current config.</summary>
    public async Task<IpcAgentConfig?> GetConfigAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("GetConfig", ct: ct);
        return response?.GetPayload<IpcAgentConfig>();
    }

    /// <summary>Update the agent's config.</summary>
    public async Task<IpcAgentConfig?> SetConfigAsync(IpcAgentConfig config, CancellationToken ct = default)
    {
        var response = await SendRequestAsync("SetConfig", config, ct);
        return response?.GetPayload<IpcAgentConfig>();
    }

    /// <summary>Get the agent's response policy (overrides and rules).</summary>
    public async Task<IpcPolicyData?> GetPolicyAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("GetPolicy", ct: ct);
        return response?.GetPayload<IpcPolicyData>();
    }

    /// <summary>Update the agent's response policy.</summary>
    public async Task<IpcPolicyData?> SetPolicyAsync(IpcPolicyData policy, CancellationToken ct = default)
    {
        var response = await SendRequestAsync("SetPolicy", policy, ct);
        return response?.GetPayload<IpcPolicyData>();
    }

    /// <summary>Send a chat message to the agent and get a rich response.</summary>
    public async Task<IpcChatResponse?> SendChatAsync(string message, CancellationToken ct = default)
    {
        var response = await SendRequestAsync("SendChat", new { message }, ct);
        return response?.GetPayload<IpcChatResponse>();
    }

    /// <summary>Request a fix execution.</summary>
    public async Task<IpcFixResult?> RunFixAsync(string fixCommand, string? findingTitle = null, bool dryRun = false, CancellationToken ct = default)
    {
        var response = await SendRequestAsync("RunFix", new { fixCommand, findingTitle, dryRun }, ct);
        return response?.GetPayload<IpcFixResult>();
    }

    /// <summary>Subscribe to live events from the agent.</summary>
    public async Task<bool> SubscribeAsync(CancellationToken ct = default)
    {
        var response = await SendRequestAsync("Subscribe", ct: ct);
        return response?.Type == "Subscribed";
    }

    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Dictionary<string, TaskCompletionSource<IpcResponse>> _pending = new();

    private async Task<IpcResponse?> SendRequestAsync(string type, object? payload = null, CancellationToken ct = default)
    {
        if (_writer == null || !IsConnected) return null;

        var requestId = Guid.NewGuid().ToString("N")[..8];
        var tcs = new TaskCompletionSource<IpcResponse>();

        lock (_pending)
        {
            _pending[requestId] = tcs;
        }

        try
        {
            var message = new IpcRequest
            {
                Type = type,
                RequestId = requestId,
                Payload = payload != null ? JsonSerializer.SerializeToElement(payload, _jsonOptions) : null
            };

            await _sendLock.WaitAsync(ct);
            try
            {
                await _writer.WriteLineAsync(JsonSerializer.Serialize(message, _jsonOptions));
            }
            finally
            {
                _sendLock.Release();
            }

            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            linkedCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        catch
        {
            return null;
        }
        finally
        {
            lock (_pending)
            {
                _pending.Remove(requestId);
            }
        }
    }

    private async Task EventLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _reader != null && IsConnected)
            {
                var line = await _reader.ReadLineAsync(ct);
                if (line == null) break;

                var response = JsonSerializer.Deserialize<IpcResponse>(line, _jsonOptions);
                if (response == null) continue;

                // Check if this is a response to a pending request
                if (response.RequestId != null)
                {
                    TaskCompletionSource<IpcResponse>? tcs;
                    lock (_pending)
                    {
                        _pending.TryGetValue(response.RequestId, out tcs);
                    }
                    if (tcs != null)
                    {
                        tcs.TrySetResult(response);
                        continue;
                    }
                }

                // Handle pushed events
                HandleEvent(response);
            }
        }
        catch (OperationCanceledException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        catch (IOException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        finally
        {
            FireDisconnected();
        }
    }

    private void HandleEvent(IpcResponse response)
    {
        switch (response.Type)
        {
            case "ThreatDetected":
                var threat = response.GetPayload<IpcThreatEvent>();
                if (threat != null) ThreatDetected?.Invoke(threat);
                break;

            case "ScanProgress":
                var progress = response.GetPayload<IpcScanProgress>();
                if (progress != null) ScanProgressReceived?.Invoke(progress);
                break;

            case "AuditCompleted":
                var scorePayload = response.GetPayload<ScorePayload>();
                if (scorePayload != null) AuditCompleted?.Invoke(scorePayload.Score);
                break;

            case "AgentShutdown":
                AgentShutdown?.Invoke();
                break;
        }
    }

    /// <summary>Fire Disconnected at most once to prevent duplicate event notifications.</summary>
    private void FireDisconnected()
    {
        if (Interlocked.Exchange(ref _disconnectedFired, 1) == 0)
        {
            Disconnected?.Invoke();
        }
    }

    private void Cleanup()
    {
        _reader?.Dispose();
        _writer?.Dispose();
        _pipe?.Dispose();
        _reader = null;
        _writer = null;
        _pipe = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _eventCts?.Cancel();

        // Wait briefly for event loop to finish before disposing shared resources
        try
        {
            _eventLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException) { /* Swallow cancellation/IO exceptions */ }
        catch (ObjectDisposedException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        Cleanup();
        _sendLock.Dispose();
        _eventCts?.Dispose();
        GC.SuppressFinalize(this);
    }

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

// ── IPC DTOs (shared between client and agent) ──

/// <summary>
/// Wire-level request envelope sent from the WPF app to the agent over the
/// <c>WinSentinel</c> named pipe. One request per line of JSON.
/// </summary>
public class IpcRequest
{
    /// <summary>Request type discriminator (e.g. <c>GetStatus</c>, <c>RunAudit</c>, <c>SendChat</c>).</summary>
    public string Type { get; set; } = "";
    /// <summary>Correlation id chosen by the client; the agent echoes it back on the matching response.</summary>
    public string? RequestId { get; set; }
    /// <summary>Optional, request-type-specific payload (camelCase JSON).</summary>
    public JsonElement? Payload { get; set; }
}

/// <summary>
/// Wire-level response envelope sent from the agent back to the WPF app. Also
/// used for unsolicited push events (no <see cref="RequestId"/>).
/// </summary>
public class IpcResponse
{
    /// <summary>
    /// Shared options for deserialization. System.Text.Json caches reflection
    /// metadata per JsonSerializerOptions instance, so reusing a single instance
    /// avoids repeated metadata generation on every GetPayload call.
    /// </summary>
    private static readonly JsonSerializerOptions s_payloadOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Response type discriminator or pushed-event name (e.g. <c>Pong</c>, <c>ThreatDetected</c>).</summary>
    public string Type { get; set; } = "";
    /// <summary>Correlation id echoed from the originating <see cref="IpcRequest"/>; <see langword="null"/> for unsolicited events.</summary>
    public string? RequestId { get; set; }
    /// <summary>Optional response-type-specific payload (camelCase JSON).</summary>
    public JsonElement? Payload { get; set; }
    /// <summary>Error description set by the agent when a request failed.</summary>
    public string? Error { get; set; }

    /// <summary>
    /// Deserialize <see cref="Payload"/> into the requested type using shared, cached
    /// JSON options. Returns <see langword="default"/> when the payload is absent.
    /// </summary>
    public T? GetPayload<T>()
    {
        if (Payload == null) return default;
        return JsonSerializer.Deserialize<T>(Payload.Value.GetRawText(), s_payloadOptions);
    }
}

/// <summary>Snapshot of the agent's runtime state returned by <c>GetStatus</c>.</summary>
public class IpcAgentStatus
{
    /// <summary>UTC time at which the agent process started.</summary>
    public DateTimeOffset StartTime { get; set; }
    /// <summary>Seconds elapsed since <see cref="StartTime"/>.</summary>
    public long UptimeSeconds { get; set; }
    /// <summary>Count of threat events surfaced today (rolling, local-day boundary on the agent).</summary>
    public int ThreatsDetectedToday { get; set; }
    /// <summary>UTC time of the most recently completed audit scan, or <see langword="null"/> if none yet.</summary>
    public DateTimeOffset? LastScanTime { get; set; }
    /// <summary>Security score (0-100) from the last completed scan, or <see langword="null"/> if none yet.</summary>
    public int? LastScanScore { get; set; }
    /// <summary>True when an audit scan is currently in progress.</summary>
    public bool IsScanRunning { get; set; }
    /// <summary>Names of currently enabled audit/monitor modules.</summary>
    public List<string> ActiveModules { get; set; } = [];
    /// <summary>Assembly informational version of the running agent.</summary>
    public string Version { get; set; } = "";

    /// <summary>Human-readable rendering of <see cref="UptimeSeconds"/> (e.g. <c>"2d 4h 31m"</c>).</summary>
    public string UptimeFormatted
    {
        get
        {
            var ts = TimeSpan.FromSeconds(UptimeSeconds);
            if (ts.TotalDays >= 1) return $"{(int)ts.TotalDays}d {ts.Hours}h {ts.Minutes}m";
            if (ts.TotalHours >= 1) return $"{ts.Hours}h {ts.Minutes}m";
            return $"{ts.Minutes}m {ts.Seconds}s";
        }
    }
}

/// <summary>A threat or finding raised by an audit/monitor module.</summary>
public class IpcThreatEvent
{
    /// <summary>Stable identifier for the event (used for de-duplication and overrides).</summary>
    public string Id { get; set; } = "";
    /// <summary>UTC time the event was raised by the agent.</summary>
    public DateTimeOffset Timestamp { get; set; }
    /// <summary>Module or detector that produced the event (e.g. <c>ProcessMonitor</c>).</summary>
    public string Source { get; set; } = "";
    /// <summary>Severity classification (<c>Critical</c>, <c>Warning</c>, <c>Info</c>).</summary>
    public string Severity { get; set; } = "";
    /// <summary>Short, user-facing title of the finding.</summary>
    public string Title { get; set; } = "";
    /// <summary>Detailed description, including evidence and rationale.</summary>
    public string Description { get; set; } = "";
    /// <summary>True when the agent can offer an automated remediation for this finding.</summary>
    public bool AutoFixable { get; set; }
    /// <summary>If a response policy fired, the action taken (e.g. <c>Quarantine</c>, <c>Ignored</c>).</summary>
    public string? ResponseTaken { get; set; }
    /// <summary>When <see cref="AutoFixable"/> is true, the remediation command the agent will execute.</summary>
    public string? FixCommand { get; set; }
}

/// <summary>Per-module progress update pushed during an in-flight audit scan.</summary>
public class IpcScanProgress
{
    /// <summary>Name of the module currently being executed.</summary>
    public string Module { get; set; } = "";
    /// <summary>Number of modules completed so far (1-based).</summary>
    public int Current { get; set; }
    /// <summary>Total number of modules in this scan.</summary>
    public int Total { get; set; }
}

/// <summary>User-tunable agent configuration round-tripped over IPC.</summary>
public class IpcAgentConfig
{
    /// <summary>Interval, in hours, between automatic background scans.</summary>
    public double ScanIntervalHours { get; set; }
    /// <summary>When true, the agent auto-remediates findings classified Critical.</summary>
    public bool AutoFixCritical { get; set; }
    /// <summary>When true, the agent auto-remediates findings classified Warning.</summary>
    public bool AutoFixWarnings { get; set; }
    /// <summary>Global risk-tolerance band (<c>Low</c>, <c>Medium</c>, <c>High</c>) governing default responses.</summary>
    public string RiskTolerance { get; set; } = "Medium";
    /// <summary>Per-module enable/disable flags keyed by module name.</summary>
    public Dictionary<string, bool> ModuleToggles { get; set; } = new();
    /// <summary>Maximum number of threat events retained in the rolling log on disk.</summary>
    public int MaxThreatLogSize { get; set; }
    /// <summary>Show a desktop notification when a Critical threat is detected.</summary>
    public bool NotifyOnCriticalThreats { get; set; }
    /// <summary>Show a desktop notification when an audit scan completes.</summary>
    public bool NotifyOnScanComplete { get; set; }
    /// <summary>Play a sound with notifications.</summary>
    public bool NotificationSound { get; set; } = true;
    /// <summary>Suppress notifications for non-Critical findings.</summary>
    public bool NotifyCriticalOnly { get; set; }
    /// <summary>Automatically export a report after each scan completes.</summary>
    public bool AutoExportAfterScan { get; set; }
    /// <summary>Report format used by auto-export (<c>HTML</c>, <c>JSON</c>, <c>MARKDOWN</c>).</summary>
    public string AutoExportFormat { get; set; } = "HTML";
    /// <summary>Launch the WPF app at user login.</summary>
    public bool StartWithWindows { get; set; }
    /// <summary>Hide the main window to the system tray instead of taskbar on minimize.</summary>
    public bool MinimizeToTray { get; set; } = true;
    /// <summary>Per-category auto-fix overrides keyed by category name.</summary>
    public Dictionary<string, bool> CategoryAutoFix { get; set; } = new();
    /// <summary>Per-category default response keyed by category name (e.g. <c>Persistence</c> -> <c>Block</c>).</summary>
    public Dictionary<string, string> CategoryDefaultResponse { get; set; } = new();
}

/// <summary>Outcome of a remediation command executed by the agent.</summary>
public class IpcFixResult
{
    /// <summary>True if the command exited with a success status.</summary>
    public bool Success { get; set; }
    /// <summary>The command line that was executed.</summary>
    public string? Command { get; set; }
    /// <summary>Captured stdout from the command.</summary>
    public string? Output { get; set; }
    /// <summary>Captured stderr (or .NET exception message) from the command.</summary>
    public string? Error { get; set; }
    /// <summary>Process exit code, or <see langword="null"/> when the command never launched.</summary>
    public int? ExitCode { get; set; }
    /// <summary>Title of the originating finding, for correlation with the threat log.</summary>
    public string? FindingTitle { get; set; }
}

/// <summary>Rich chat response from the agent.</summary>
public class IpcChatResponse
{
    /// <summary>Free-form text reply rendered in the chat surface.</summary>
    public string Text { get; set; } = "";
    /// <summary>Quick-action buttons offered alongside the reply.</summary>
    public List<IpcSuggestedAction> SuggestedActions { get; set; } = new();
    /// <summary>Threat events referenced or surfaced by this reply.</summary>
    public List<IpcChatThreatEvent> ThreatEvents { get; set; } = new();
    /// <summary>Current overall security score (0-100), when the reply context includes it.</summary>
    public int? SecurityScore { get; set; }
    /// <summary>True when the agent already performed an action on behalf of the user.</summary>
    public bool ActionPerformed { get; set; }
    /// <summary>Identifier of the action performed (for undo / audit correlation).</summary>
    public string? ActionId { get; set; }
    /// <summary>Classification used by the UI to style the reply (e.g. <c>Threat</c>, <c>Status</c>, <c>General</c>).</summary>
    public string Category { get; set; } = "General";
}

/// <summary>Suggested action from chat response.</summary>
public class IpcSuggestedAction
{
    /// <summary>Human-readable button label shown to the user.</summary>
    public string Label { get; set; } = "";
    /// <summary>Slash-command or fix command the agent will execute if the user accepts.</summary>
    public string Command { get; set; } = "";
}

/// <summary>Threat event in chat response.</summary>
public class IpcChatThreatEvent
{
    /// <summary>Stable event identifier.</summary>
    public string Id { get; set; } = "";
    /// <summary>UTC time the event was raised.</summary>
    public DateTimeOffset Timestamp { get; set; }
    /// <summary>Detector or module that produced the event.</summary>
    public string Source { get; set; } = "";
    /// <summary>Severity classification (<c>Critical</c>, <c>Warning</c>, <c>Info</c>).</summary>
    public string Severity { get; set; } = "";
    /// <summary>Short, user-facing title of the finding.</summary>
    public string Title { get; set; } = "";
    /// <summary>Response action taken by policy (if any).</summary>
    public string? ResponseTaken { get; set; }
}

/// <summary>Internal envelope used to unpack the integer score from an <c>AuditCompleted</c> event.</summary>
internal class ScorePayload
{
    /// <summary>Security score (0-100) from the just-completed scan.</summary>
    public int Score { get; set; }
}

/// <summary>IPC data for response policy.</summary>
public class IpcPolicyData
{
    /// <summary>Ordered set of policy rules evaluated against incoming findings.</summary>
    public List<IpcPolicyRule> Rules { get; set; } = new();
    /// <summary>User-specified overrides that win over <see cref="Rules"/>.</summary>
    public List<IpcUserOverride> UserOverrides { get; set; } = new();
    /// <summary>Global risk-tolerance band that calibrates default actions.</summary>
    public string RiskTolerance { get; set; } = "Medium";
}

/// <summary>IPC policy rule.</summary>
public class IpcPolicyRule
{
    /// <summary>Category filter (e.g. <c>Persistence</c>); <see langword="null"/> matches any category.</summary>
    public string? Category { get; set; }
    /// <summary>Severity filter (<c>Critical</c>, <c>Warning</c>, <c>Info</c>); <see langword="null"/> matches any severity.</summary>
    public string? Severity { get; set; }
    /// <summary>Substring or wildcard match applied to <see cref="IpcThreatEvent.Title"/>; <see langword="null"/> matches any title.</summary>
    public string? TitlePattern { get; set; }
    /// <summary>Action to take when the rule matches (e.g. <c>Log</c>, <c>Block</c>, <c>AutoFix</c>).</summary>
    public string Action { get; set; } = "Log";
    /// <summary>Allow the agent to auto-remediate matched findings.</summary>
    public bool AllowAutoFix { get; set; } = true;
    /// <summary>Evaluation priority - higher values win when multiple rules match.</summary>
    public int Priority { get; set; }
}

/// <summary>IPC user override.</summary>
public class IpcUserOverride
{
    /// <summary>Exact threat title the override applies to.</summary>
    public string ThreatTitle { get; set; } = "";
    /// <summary>Optional source/detector scope; <see langword="null"/> applies the override across all sources.</summary>
    public string? Source { get; set; }
    /// <summary>Override decision (e.g. <c>AlwaysIgnore</c>, <c>AlwaysFix</c>, <c>AlwaysAsk</c>).</summary>
    public string OverrideAction { get; set; } = "AlwaysIgnore";
    /// <summary>UTC time the override was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }
}
