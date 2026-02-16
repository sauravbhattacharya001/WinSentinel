using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Agent.Ipc;

/// <summary>
/// IPC message types for the WinSentinel named pipe protocol.
/// </summary>
public enum IpcMessageType
{
    // Requests (UI → Agent)
    GetStatus,
    RunAudit,
    RunFix,
    GetThreats,
    GetConfig,
    SetConfig,
    SendChat,
    Subscribe,
    Unsubscribe,
    Ping,

    // Responses (Agent → UI)
    StatusResponse,
    AuditStarted,
    AuditCompleted,
    FixResult,
    ThreatsResponse,
    ConfigResponse,
    ChatResponse,
    Subscribed,
    Error,
    Pong,

    // Events (Agent → UI, pushed)
    ThreatDetected,
    ScanProgress,
    AgentShutdown
}

/// <summary>
/// Envelope for all IPC messages. JSON-serialized, one per line over the pipe.
/// </summary>
public class IpcMessage
{
    public IpcMessageType Type { get; set; }

    /// <summary>Correlation ID for request/response matching.</summary>
    public string? RequestId { get; set; }

    /// <summary>JSON payload — interpreted based on Type.</summary>
    public JsonElement? Payload { get; set; }

    /// <summary>Error message (when Type == Error).</summary>
    public string? Error { get; set; }

    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    // ── Factory methods ──

    public static IpcMessage Request(IpcMessageType type, object? payload = null, string? requestId = null) => new()
    {
        Type = type,
        RequestId = requestId ?? Guid.NewGuid().ToString("N")[..8],
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    public static IpcMessage Response(IpcMessageType type, object? payload = null, string? requestId = null) => new()
    {
        Type = type,
        RequestId = requestId,
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    public static IpcMessage ErrorResponse(string error, string? requestId = null) => new()
    {
        Type = IpcMessageType.Error,
        RequestId = requestId,
        Error = error
    };

    public static IpcMessage Event(IpcMessageType type, object? payload = null) => new()
    {
        Type = type,
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    // ── Serialization ──

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string Serialize() => JsonSerializer.Serialize(this, JsonOptions);

    public static IpcMessage? Deserialize(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<IpcMessage>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Deserialize the payload to a specific type.</summary>
    public T? GetPayload<T>()
    {
        if (Payload == null) return default;
        return JsonSerializer.Deserialize<T>(Payload.Value.GetRawText(), JsonOptions);
    }
}

/// <summary>Payload for RunFix requests.</summary>
public class RunFixPayload
{
    public string? FindingTitle { get; set; }
    public string? FixCommand { get; set; }
    public bool DryRun { get; set; }
}

/// <summary>Payload for SendChat requests.</summary>
public class ChatPayload
{
    public string Message { get; set; } = "";
}

/// <summary>Payload for scan progress events.</summary>
public class ScanProgressPayload
{
    public string Module { get; set; } = "";
    public int Current { get; set; }
    public int Total { get; set; }
}
