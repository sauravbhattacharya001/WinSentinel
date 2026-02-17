using System.Collections.Concurrent;
using System.IO.Pipes;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Named pipe server for UI ↔ Agent IPC communication.
/// Supports multiple concurrent UI clients with event streaming.
/// Pipe name: WinSentinel
/// Protocol: newline-delimited JSON (one IpcMessage per line).
/// </summary>
public class IpcServer : BackgroundService
{
    private const string PipeName = "WinSentinel";
    private readonly ILogger<IpcServer> _logger;
    private readonly AgentState _state;
    private readonly AgentConfig _config;
    private readonly ThreatLog _threatLog;
    private readonly ResponsePolicy _responsePolicy;
    private readonly ConcurrentDictionary<string, StreamWriter> _subscribers = new();
    private readonly IServiceProvider _services;

    /// <summary>Event fired when a "run audit" command is received via IPC.</summary>
    public event Func<Task>? AuditRequested;

    /// <summary>Trigger an audit (callable from ChatHandler and other internal services).</summary>
    public async Task TriggerAuditAsync()
    {
        if (AuditRequested != null)
        {
            await AuditRequested.Invoke();
        }
    }

    /// <summary>Event fired when a chat message is received via IPC.</summary>
    public event Func<string, Task<ChatResponsePayload>>? ChatMessageReceived;

    public IpcServer(
        ILogger<IpcServer> logger,
        AgentState state,
        AgentConfig config,
        ThreatLog threatLog,
        ResponsePolicy responsePolicy,
        IServiceProvider services)
    {
        _logger = logger;
        _state = state;
        _config = config;
        _threatLog = threatLog;
        _responsePolicy = responsePolicy;
        _services = services;

        // Subscribe to threat events for push notifications
        _threatLog.ThreatDetected += OnThreatDetected;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("IPC server starting on pipe: {PipeName}", PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(stoppingToken);

                var clientId = Guid.NewGuid().ToString("N")[..8];
                _logger.LogInformation("IPC client connected: {ClientId}", clientId);

                // Handle each client in a separate task
                _ = HandleClientAsync(pipe, clientId, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting IPC connection");
                await Task.Delay(1000, stoppingToken);
            }
        }

        // Notify subscribers of shutdown
        await BroadcastEventAsync(IpcMessage.Event(IpcMessageType.AgentShutdown));
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, string clientId, CancellationToken ct)
    {
        try
        {
            using (pipe)
            {
                var reader = new StreamReader(pipe);
                var writer = new StreamWriter(pipe) { AutoFlush = true };

                while (pipe.IsConnected && !ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line == null) break; // Client disconnected

                    var message = IpcMessage.Deserialize(line);
                    if (message == null)
                    {
                        await SendAsync(writer, IpcMessage.ErrorResponse("Invalid message format"));
                        continue;
                    }

                    var response = await HandleMessageAsync(message, writer, clientId);
                    if (response != null)
                    {
                        await SendAsync(writer, response);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { /* Client disconnected */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling IPC client {ClientId}", clientId);
        }
        finally
        {
            _subscribers.TryRemove(clientId, out _);
            _logger.LogInformation("IPC client disconnected: {ClientId}", clientId);
        }
    }

    private async Task<IpcMessage?> HandleMessageAsync(IpcMessage message, StreamWriter writer, string clientId)
    {
        try
        {
            return message.Type switch
            {
                IpcMessageType.Ping => IpcMessage.Response(IpcMessageType.Pong, requestId: message.RequestId),

                IpcMessageType.GetStatus => IpcMessage.Response(
                    IpcMessageType.StatusResponse,
                    _state.ToSnapshot(),
                    message.RequestId),

                IpcMessageType.RunAudit => await HandleRunAuditAsync(message),

                IpcMessageType.GetThreats => IpcMessage.Response(
                    IpcMessageType.ThreatsResponse,
                    _threatLog.GetRecent(100),
                    message.RequestId),

                IpcMessageType.GetConfig => IpcMessage.Response(
                    IpcMessageType.ConfigResponse,
                    _config.ToSnapshot(),
                    message.RequestId),

                IpcMessageType.SetConfig => HandleSetConfig(message),

                IpcMessageType.GetPolicy => HandleGetPolicy(message),

                IpcMessageType.SetPolicy => HandleSetPolicy(message),

                IpcMessageType.SendChat => await HandleChatAsync(message),

                IpcMessageType.Subscribe => HandleSubscribe(writer, clientId, message),

                IpcMessageType.Unsubscribe => HandleUnsubscribe(clientId, message),

                IpcMessageType.RunFix => await HandleRunFixAsync(message),

                _ => IpcMessage.ErrorResponse($"Unknown message type: {message.Type}", message.RequestId)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling IPC message type {Type}", message.Type);
            return IpcMessage.ErrorResponse(ex.Message, message.RequestId);
        }
    }

    private Task<IpcMessage> HandleRunAuditAsync(IpcMessage message)
    {
        if (_state.IsScanRunning)
            return Task.FromResult(IpcMessage.ErrorResponse("A scan is already running.", message.RequestId));

        // Fire and forget — the audit module handles it
        if (AuditRequested != null)
        {
            _ = Task.Run(async () =>
            {
                try { await AuditRequested.Invoke(); }
                catch (Exception ex) { _logger.LogError(ex, "Error running requested audit"); }
            });
        }

        return Task.FromResult(IpcMessage.Response(IpcMessageType.AuditStarted, requestId: message.RequestId));
    }

    private IpcMessage HandleSetConfig(IpcMessage message)
    {
        var snapshot = message.GetPayload<AgentConfigSnapshot>();
        if (snapshot == null)
            return IpcMessage.ErrorResponse("Invalid config payload.", message.RequestId);

        _config.ApplySnapshot(snapshot);
        return IpcMessage.Response(IpcMessageType.ConfigResponse, _config.ToSnapshot(), message.RequestId);
    }

    private IpcMessage HandleGetPolicy(IpcMessage message)
    {
        var payload = new PolicyPayload
        {
            RiskTolerance = _responsePolicy.RiskTolerance.ToString(),
            Rules = _responsePolicy.Rules.Select(r => new PolicyRulePayload
            {
                Category = r.Category?.ToString(),
                Severity = r.Severity?.ToString(),
                TitlePattern = r.TitlePattern,
                Action = r.Action.ToString(),
                AllowAutoFix = r.AllowAutoFix,
                Priority = r.Priority
            }).ToList(),
            UserOverrides = _responsePolicy.UserOverrides.Select(o => new UserOverridePayload
            {
                ThreatTitle = o.ThreatTitle,
                Source = o.Source,
                OverrideAction = o.OverrideAction.ToString(),
                CreatedAt = o.CreatedAt
            }).ToList()
        };

        return IpcMessage.Response(IpcMessageType.PolicyResponse, payload, message.RequestId);
    }

    private IpcMessage HandleSetPolicy(IpcMessage message)
    {
        var payload = message.GetPayload<PolicyPayload>();
        if (payload == null)
            return IpcMessage.ErrorResponse("Invalid policy payload.", message.RequestId);

        // Update risk tolerance
        if (Enum.TryParse<RiskTolerance>(payload.RiskTolerance, out var rt))
            _responsePolicy.RiskTolerance = rt;

        // Replace user overrides
        _responsePolicy.UserOverrides.Clear();
        foreach (var o in payload.UserOverrides)
        {
            if (Enum.TryParse<UserOverrideAction>(o.OverrideAction, out var action))
            {
                _responsePolicy.UserOverrides.Add(new UserOverride
                {
                    ThreatTitle = o.ThreatTitle,
                    Source = o.Source,
                    OverrideAction = action,
                    CreatedAt = o.CreatedAt
                });
            }
        }

        _responsePolicy.Save();

        return HandleGetPolicy(message);
    }

    private async Task<IpcMessage> HandleChatAsync(IpcMessage message)
    {
        var payload = message.GetPayload<ChatPayload>();
        if (payload == null || string.IsNullOrWhiteSpace(payload.Message))
            return IpcMessage.ErrorResponse("Empty chat message.", message.RequestId);

        ChatResponsePayload response;
        if (ChatMessageReceived != null)
        {
            response = await ChatMessageReceived.Invoke(payload.Message);
        }
        else
        {
            response = new ChatResponsePayload
            {
                Text = "Agent chat is not configured. Use the WPF app's built-in AI chat instead.",
                Category = ChatResponseCategory.Error
            };
        }

        return IpcMessage.Response(IpcMessageType.ChatResponse, response, message.RequestId);
    }

    private IpcMessage HandleSubscribe(StreamWriter writer, string clientId, IpcMessage message)
    {
        _subscribers[clientId] = writer;
        _logger.LogInformation("Client {ClientId} subscribed to events", clientId);
        return IpcMessage.Response(IpcMessageType.Subscribed, requestId: message.RequestId);
    }

    private IpcMessage HandleUnsubscribe(string clientId, IpcMessage message)
    {
        _subscribers.TryRemove(clientId, out _);
        _logger.LogInformation("Client {ClientId} unsubscribed from events", clientId);
        return IpcMessage.Response(IpcMessageType.Subscribed, requestId: message.RequestId);
    }

    private async Task<IpcMessage> HandleRunFixAsync(IpcMessage message)
    {
        var payload = message.GetPayload<RunFixPayload>();
        if (payload == null || string.IsNullOrWhiteSpace(payload.FixCommand))
            return IpcMessage.ErrorResponse("No fix command provided.", message.RequestId);

        var fixEngine = new FixEngine();
        var finding = new WinSentinel.Core.Models.Finding
        {
            Title = payload.FindingTitle ?? "IPC Fix",
            Description = "Fix requested via IPC",
            FixCommand = payload.FixCommand
        };

        var result = await fixEngine.ExecuteFixAsync(finding, payload.DryRun);
        return IpcMessage.Response(IpcMessageType.FixResult, result, message.RequestId);
    }

    /// <summary>Broadcast a scan progress event to all subscribers.</summary>
    public async Task BroadcastScanProgressAsync(string module, int current, int total)
    {
        var payload = new ScanProgressPayload { Module = module, Current = current, Total = total };
        await BroadcastEventAsync(IpcMessage.Event(IpcMessageType.ScanProgress, payload));
    }

    /// <summary>Broadcast an audit completed event to all subscribers.</summary>
    public async Task BroadcastAuditCompletedAsync(int score)
    {
        await BroadcastEventAsync(IpcMessage.Event(IpcMessageType.AuditCompleted, new { Score = score }));
    }

    private void OnThreatDetected(ThreatEvent threat)
    {
        _ = BroadcastEventAsync(IpcMessage.Event(IpcMessageType.ThreatDetected, threat));
    }

    private async Task BroadcastEventAsync(IpcMessage message)
    {
        var deadClients = new List<string>();

        foreach (var (clientId, writer) in _subscribers)
        {
            try
            {
                await SendAsync(writer, message);
            }
            catch
            {
                deadClients.Add(clientId);
            }
        }

        foreach (var id in deadClients)
        {
            _subscribers.TryRemove(id, out _);
        }
    }

    private static async Task SendAsync(StreamWriter writer, IpcMessage message)
    {
        await writer.WriteLineAsync(message.Serialize());
    }
}
