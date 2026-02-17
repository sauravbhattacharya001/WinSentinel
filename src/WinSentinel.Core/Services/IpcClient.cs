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
        Disconnected?.Invoke();
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
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (Exception) { }
        finally
        {
            Disconnected?.Invoke();
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

public class IpcRequest
{
    public string Type { get; set; } = "";
    public string? RequestId { get; set; }
    public JsonElement? Payload { get; set; }
}

public class IpcResponse
{
    public string Type { get; set; } = "";
    public string? RequestId { get; set; }
    public JsonElement? Payload { get; set; }
    public string? Error { get; set; }

    public T? GetPayload<T>()
    {
        if (Payload == null) return default;
        return JsonSerializer.Deserialize<T>(Payload.Value.GetRawText(), new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
    }
}

public class IpcAgentStatus
{
    public DateTimeOffset StartTime { get; set; }
    public long UptimeSeconds { get; set; }
    public int ThreatsDetectedToday { get; set; }
    public DateTimeOffset? LastScanTime { get; set; }
    public int? LastScanScore { get; set; }
    public bool IsScanRunning { get; set; }
    public List<string> ActiveModules { get; set; } = [];
    public string Version { get; set; } = "";

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

public class IpcThreatEvent
{
    public string Id { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public string Source { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public bool AutoFixable { get; set; }
    public string? ResponseTaken { get; set; }
    public string? FixCommand { get; set; }
}

public class IpcScanProgress
{
    public string Module { get; set; } = "";
    public int Current { get; set; }
    public int Total { get; set; }
}

public class IpcAgentConfig
{
    public double ScanIntervalHours { get; set; }
    public bool AutoFixCritical { get; set; }
    public bool AutoFixWarnings { get; set; }
    public string RiskTolerance { get; set; } = "Medium";
    public Dictionary<string, bool> ModuleToggles { get; set; } = new();
    public int MaxThreatLogSize { get; set; }
    public bool NotifyOnCriticalThreats { get; set; }
    public bool NotifyOnScanComplete { get; set; }
}

public class IpcFixResult
{
    public bool Success { get; set; }
    public string? Command { get; set; }
    public string? Output { get; set; }
    public string? Error { get; set; }
    public int? ExitCode { get; set; }
    public string? FindingTitle { get; set; }
}

/// <summary>Rich chat response from the agent.</summary>
public class IpcChatResponse
{
    public string Text { get; set; } = "";
    public List<IpcSuggestedAction> SuggestedActions { get; set; } = new();
    public List<IpcChatThreatEvent> ThreatEvents { get; set; } = new();
    public int? SecurityScore { get; set; }
    public bool ActionPerformed { get; set; }
    public string? ActionId { get; set; }
    public string Category { get; set; } = "General";
}

/// <summary>Suggested action from chat response.</summary>
public class IpcSuggestedAction
{
    public string Label { get; set; } = "";
    public string Command { get; set; } = "";
}

/// <summary>Threat event in chat response.</summary>
public class IpcChatThreatEvent
{
    public string Id { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public string Source { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Title { get; set; } = "";
    public string? ResponseTaken { get; set; }
}

internal class ScorePayload
{
    public int Score { get; set; }
}
